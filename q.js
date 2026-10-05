#!/usr/bin/env node

const inquirer = require('inquirer');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CONFIG_FILE = path.join(os.homedir(), '.bandwidth-config.json');
const DEVICES_FILE = path.join(os.homedir(), '.connected-devices.json');

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
  bold: '\x1b[1m'
};

const success = (msg) => console.log(`${colors.green}${colors.bold}✅ ${msg}${colors.reset}`);
const error = (msg) => console.log(`${colors.red}${colors.bold}❌ ${msg}${colors.reset}`);
const info = (msg) => console.log(`${colors.cyan}${colors.bold}ℹ️  ${msg}${colors.reset}`);
const warn = (msg) => console.log(`${colors.yellow}${colors.bold}⚠️  ${msg}${colors.reset}`);

class DeviceManager {
  constructor() {
    this.devices = new Map();
    this.loadDevices();
  }

  loadDevices() {
    try {
      if (fs.existsSync(DEVICES_FILE)) {
        const data = JSON.parse(fs.readFileSync(DEVICES_FILE, 'utf8'));
        this.devices = new Map(Object.entries(data));
      }
    } catch (err) {
      warn(`Gagal load devices`);
    }
  }

  saveDevices() {
    try {
      const data = Object.fromEntries(this.devices);
      fs.writeFileSync(DEVICES_FILE, JSON.stringify(data, null, 2));
    } catch (err) {
      warn(`Gagal save devices`);
    }
  }

  addDevice(mac, name, ipAddress, isCurrentDevice = false) {
    this.devices.set(mac, {
      mac, name, ipAddress, isCurrentDevice,
      addedAt: new Date().toISOString(),
      status: 'CONNECTED'
    });
    this.saveDevices();
    return true;
  }

  removeDevice(mac) {
    this.devices.delete(mac);
    this.saveDevices();
    return true;
  }

  disconnectDevice(mac) {
    const device = this.devices.get(mac);
    if (device) {
      device.status = 'DISCONNECTED';
      device.disconnectedAt = new Date().toISOString();
      this.saveDevices();
    }
    return true;
  }

  getDevice(mac) {
    return this.devices.get(mac) || null;
  }

  getAllDevices() {
    return Array.from(this.devices.values());
  }

  getConnectedDevices() {
    return Array.from(this.devices.values()).filter(d => d.status === 'CONNECTED');
  }

  getCurrentDevice() {
    return Array.from(this.devices.values()).find(d => d.isCurrentDevice);
  }

  getOtherDevices() {
    return Array.from(this.devices.values()).filter(d => !d.isCurrentDevice && d.status === 'CONNECTED');
  }
}

class BandwidthManager {
  constructor() {
    this.limits = new Map();
    this.loadConfig();
  }

  loadConfig() {
    try {
      if (fs.existsSync(CONFIG_FILE)) {
        const data = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        this.limits = new Map(Object.entries(data));
      }
    } catch (err) {
      warn(`Gagal load config`);
    }
  }

  saveConfig() {
    try {
      const data = Object.fromEntries(this.limits);
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2));
    } catch (err) {
      warn(`Gagal save config`);
    }
  }

  setLimit(identifier, downloadSpeed, uploadSpeed, type = 'interface', includeSelf = false) {
    this.limits.set(identifier, {
      identifier, download: downloadSpeed, upload: uploadSpeed, type, includeSelf,
      timestamp: new Date().toISOString(),
      status: 'ACTIVE'
    });
    this.saveConfig();
    return true;
  }

  removeLimit(identifier) {
    this.limits.delete(identifier);
    this.saveConfig();
    return true;
  }

  getLimit(identifier) {
    return this.limits.get(identifier) || null;
  }

  getAllLimits() {
    return Array.from(this.limits.values());
  }

  simulateTraffic(identifier) {
    const limit = this.getLimit(identifier);
    if (!limit) return { status: 'NO_LIMIT' };
    
    const randomFactor = Math.random() * 0.9;
    return {
      identifier,
      limitDownload: limit.download,
      limitUpload: limit.upload,
      actualDownload: (limit.download * randomFactor).toFixed(2),
      actualUpload: (limit.upload * randomFactor).toFixed(2),
      usagePercentage: Math.round(randomFactor * 100),
      timestamp: new Date().toISOString()
    };
  }

  generateReport() {
    const limits = this.getAllLimits();
    if (limits.length === 0) return null;
    
    return {
      totalLimits: limits.length,
      limits: limits.map(limit => ({
        ...limit,
        totalLimit: limit.download + limit.upload,
        traffic: this.simulateTraffic(limit.identifier)
      })),
      generatedAt: new Date().toISOString()
    };
  }
}

class NetworkManager {
  constructor() {
    this.interfaces = this.getSystemInterfaces();
    this.currentIP = this.getCurrentIP();
  }

  getSystemInterfaces() {
    const networkInterfaces = os.networkInterfaces();
    const interfaces = [];

    Object.keys(networkInterfaces).forEach(name => {
      if (name !== 'lo') {
        const details = networkInterfaces[name];
        const hasIPv4 = details.some(addr => addr.family === 'IPv4');
        
        if (hasIPv4) {
          const ipv4 = details.find(addr => addr.family === 'IPv4');
          interfaces.push({
            name, 
            type: this.getInterfaceType(name),
            status: 'UP',
            ipv4: ipv4?.address || 'N/A',
            mac: ipv4?.mac || 'N/A'
          });
        }
      }
    });
    return interfaces;
  }

  getCurrentIP() {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      for (const iface of ifaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }

  getInterfaceType(name) {
    if (name.includes('wifi') || name.includes('wlan')) return '📡 WiFi';
    if (name.includes('eth') || name.includes('en')) return '🔌 Ethernet';
    if (name.includes('docker')) return '🐳 Docker';
    return '🌐 Network';
  }

  getAllInterfaces() {
    return this.interfaces;
  }

  generateMockDevices(count = 5) {
    const devices = [];
    for (let i = 1; i <= count; i++) {
      devices.push({
        mac: this.generateRandomMAC(),
        name: `Device ${i}`,
        ipAddress: `192.168.1.${100 + i}`,
        isCurrentDevice: i === 1
      });
    }
    return devices;
  }

  generateRandomMAC() {
    return Array.from({ length: 6 }, () => 
      Math.floor(Math.random() * 16).toString(16).padStart(2, '0')
    ).join(':');
  }

  runSpeedTest(identifier) {
    const baseSpeed = Math.random() * 100 + 20;
    return {
      identifier,
      downloadSpeed: Math.round(baseSpeed),
      uploadSpeed: Math.round(baseSpeed * 0.5),
      ping: Math.round(Math.random() * 50 + 10),
      jitter: Math.round(Math.random() * 10),
      timestamp: new Date().toISOString()
    };
  }
}

class App {
  constructor() {
    this.bandwidthManager = new BandwidthManager();
    this.networkManager = new NetworkManager();
    this.deviceManager = new DeviceManager();
  }

  showBanner() {
    console.clear();
    console.log(`${colors.cyan}${colors.bold}
╔════════════════════════════════════════════════════╗
║     🌐 BANDWIDTH LIMITER - Advanced Edition 🌐    ║
║   Kontrol Internet Traffic & Kelola Device       ║
╚════════════════════════════════════════════════════╝
${colors.reset}`);
  }

  showActiveLimits() {
    const limits = this.bandwidthManager.getAllLimits();
    if (limits.length === 0) {
      console.log(`${colors.gray}   (Belum ada limit yang aktif)\n${colors.reset}`);
      return;
    }

    console.log(`${colors.magenta}${colors.bold}\n📦 Active Limits:${colors.reset}`);
    limits.forEach((limit, idx) => {
      const typeLabel = limit.type === 'device' ? '📱' : '🌐';
      const selfLabel = limit.includeSelf ? ' (Termasuk Anda)' : ' (Kecuali Anda)';
      console.log(`${colors.gray}   ${idx + 1}. ${typeLabel} ${limit.identifier}${limit.type === 'device' ? selfLabel : ''}${colors.reset}`);
      console.log(`${colors.cyan}      ↓ ${limit.download}Mbps ↑ ${limit.upload}Mbps${colors.reset}`);
      console.log(`${colors.gray}      ⏰ ${limit.timestamp}${colors.reset}\n`);
    });
  }

  async mainMenu() {
    this.showBanner();
    this.showActiveLimits();

    const answers = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: `${colors.cyan}Pilih menu:${colors.reset}`,
        choices: [
          { name: '⚡ Set Bandwidth (Interface)', value: 'limit' },
          { name: '📱 Kelola Device', value: 'device' },
          { name: '🔄 Hapus Limit', value: 'remove' },
          { name: '📊 Lihat Status', value: 'status' },
          { name: '🚫 Disconnect Semua Device', value: 'disconnect' },
          { name: '📡 Speed Test', value: 'speedtest' },
          { name: '🔍 Network Interface', value: 'interfaces' },
          { name: '📈 Report', value: 'report' },
          { name: '❌ Keluar', value: 'exit' }
        ]
      }
    ]);

    switch (answers.action) {
      case 'limit': await this.limitMenu(); break;
      case 'device': await this.deviceMenu(); break;
      case 'remove': await this.removeMenu(); break;
      case 'status': await this.statusMenu(); break;
      case 'disconnect': await this.disconnectAllMenu(); break;
      case 'speedtest': await this.speedTestMenu(); break;
      case 'interfaces': await this.interfacesMenu(); break;
      case 'report': await this.reportMenu(); break;
      case 'exit':
        console.log(`${colors.yellow}${colors.bold}\n👋 Selamat tinggal!\n${colors.reset}`);
        process.exit(0);
    }

    await this.askContinue();
  }

  async limitMenu() {
    console.log();
    const interfaces = this.networkManager.getAllInterfaces();

    if (interfaces.length === 0) {
      error('Tidak ada interface!');
      return;
    }

    const answer1 = await inquirer.prompt([
      {
        type: 'list',
        name: 'interface',
        message: `${colors.cyan}Pilih interface:${colors.reset}`,
        choices: interfaces.map(i => ({
          name: `${i.type} ${i.name} (${i.ipv4})`,
          value: i.name
        }))
      }
    ]);

    const answer2 = await inquirer.prompt([
      {
        type: 'list',
        name: 'speedType',
        message: `${colors.cyan}Pilih kecepatan:${colors.reset}`,
        choices: [
          { name: '🐢 1Mbps', value: 1 },
          { name: '🐌 5Mbps', value: 5 },
          { name: '⚠️  10Mbps', value: 10 },
          { name: '📱 20Mbps', value: 20 },
          { name: '⚡ 50Mbps', value: 50 },
          { name: '🚀 100Mbps', value: 100 },
          { name: '✨ Custom', value: 'custom' }
        ]
      }
    ]);

    let downloadSpeed = 0;
    let uploadSpeed = 0;

    if (answer2.speedType === 'custom') {
      const custom = await inquirer.prompt([
        { type: 'number', name: 'download', message: 'Download (Mbps):', default: 10 },
        { type: 'number', name: 'upload', message: 'Upload (Mbps):', default: 5 }
      ]);
      downloadSpeed = custom.download;
      uploadSpeed = custom.upload;
    } else {
      downloadSpeed = Number(answer2.speedType);
      uploadSpeed = Math.round(downloadSpeed / 2);
    }

    const result = this.bandwidthManager.setLimit(answer1.interface, downloadSpeed, uploadSpeed, 'interface');
    
    if (result) {
      console.log();
      success(`Limit di-set!`);
      console.log(`${colors.green}   Interface: ${answer1.interface}${colors.reset}`);
      console.log(`${colors.green}   ↓ ${downloadSpeed}Mbps ↑ ${uploadSpeed}Mbps${colors.reset}`);
      console.log();
    }
  }

  async deviceMenu() {
    console.log();
    const action = await inquirer.prompt([
      {
        type: 'list',
        name: 'choice',
        message: `${colors.cyan}Pilih aksi:${colors.reset}`,
        choices: [
          { name: '➕ Tambah Device', value: 'add' },
          { name: '⚡ Batasi Semua Device', value: 'limitAll' },
          { name: '⚡ Batasi 1 Device', value: 'limitOne' },
          { name: '📋 Lihat Device', value: 'list' },
          { name: '🔙 Kembali', value: 'back' }
        ]
      }
    ]);

    switch (action.choice) {
      case 'add': await this.addDeviceMenu(); break;
      case 'limitAll': await this.limitAllDevicesMenu(); break;
      case 'limitOne': await this.limitOneDeviceMenu(); break;
      case 'list': await this.listDevicesMenu(); break;
    }
  }

  async addDeviceMenu() {
    console.log();
    const mockDevices = this.networkManager.generateMockDevices(5);
    
    const answer = await inquirer.prompt([
      {
        type: 'list',
        name: 'device',
        message: `${colors.cyan}Pilih device:${colors.reset}`,
        choices: [
          ...mockDevices.map(d => ({
            name: `${d.name} (${d.ipAddress})`,
            value: JSON.stringify(d)
          })),
          { name: '✏️  Manual', value: 'manual' }
        ]
      }
    ]);

    let device;
    if (answer.device === 'manual') {
      const manual = await inquirer.prompt([
        { type: 'input', name: 'name', message: 'Nama:', default: 'Device' },
        { type: 'input', name: 'ipAddress', message: 'IP:', default: '192.168.1.100' },
        { type: 'input', name: 'mac', message: 'MAC:', default: this.networkManager.generateRandomMAC() }
      ]);
      device = { ...manual, isCurrentDevice: false };
    } else {
      device = JSON.parse(answer.device);
    }

    const result = this.deviceManager.addDevice(device.mac, device.name, device.ipAddress, false);
    
    if (result) {
      console.log();
      success(`Device ${device.name} ditambahkan!`);
      console.log(`${colors.green}   MAC: ${device.mac}${colors.reset}`);
      console.log();
    }
  }

  async limitAllDevicesMenu() {
    console.log();
    const devices = this.deviceManager.getConnectedDevices();

    if (devices.length === 0) {
      warn('Tidak ada device!');
      return;
    }

    const answer1 = await inquirer.prompt([
      {
        type: 'list',
        name: 'speedType',
        message: `${colors.cyan}Kecepatan:${colors.reset}`,
        choices: [
          { name: '🐢 1Mbps', value: 1 },
          { name: '🐌 5Mbps', value: 5 },
          { name: '⚠️  10Mbps', value: 10 },
          { name: '📱 20Mbps', value: 20 },
          { name: '⚡ 50Mbps', value: 50 },
          { name: '🚀 100Mbps', value: 100 },
          { name: '✨ Custom', value: 'custom' }
        ]
      }
    ]);

    let downloadSpeed = 0;
    let uploadSpeed = 0;

    if (answer1.speedType === 'custom') {
      const custom = await inquirer.prompt([
        { type: 'number', name: 'download', message: 'Download:', default: 10 },
        { type: 'number', name: 'upload', message: 'Upload:', default: 5 }
      ]);
      downloadSpeed = custom.download;
      uploadSpeed = custom.upload;
    } else {
      downloadSpeed = Number(answer1.speedType);
      uploadSpeed = Math.round(downloadSpeed / 2);
    }

    const answer2 = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'includeSelf',
        message: `${colors.yellow}Termasuk device Anda?${colors.reset}`,
        default: false
      }
    ]);

    console.log();
    info('Menerapkan limit...');

    let count = 0;
    devices.forEach(device => {
      if (!answer2.includeSelf && device.isCurrentDevice) return;
      
      this.bandwidthManager.setLimit(device.mac, downloadSpeed, uploadSpeed, 'device', answer2.includeSelf);
      count++;
    });

    console.log();
    success(`${count} device di-limit!`);
    console.log(`${colors.green}   ↓ ${downloadSpeed}Mbps ↑ ${uploadSpeed}Mbps${colors.reset}`);
    console.log();
  }

  async limitOneDeviceMenu() {
    console.log();
    const devices = this.deviceManager.getConnectedDevices();

    if (devices.length === 0) {
      warn('Tidak ada device!');
      return;
    }

    const answer1 = await inquirer.prompt([
      {
        type: 'list',
        name: 'device',
        message: `${colors.cyan}Pilih device:${colors.reset}`,
        choices: devices.map(d => ({
          name: `${d.name} (${d.ipAddress})`,
          value: d.mac
        }))
      }
    ]);

    const answer2 = await inquirer.prompt([
      {
        type: 'list',
        name: 'speedType',
        message: `${colors.cyan}Kecepatan:${colors.reset}`,
        choices: [
          { name: '🐢 1Mbps', value: 1 },
          { name: '🐌 5Mbps', value: 5 },
          { name: '⚠️  10Mbps', value: 10 },
          { name: '📱 20Mbps', value: 20 },
          { name: '⚡ 50Mbps', value: 50 },
          { name: '🚀 100Mbps', value: 100 },
          { name: '✨ Custom', value: 'custom' }
        ]
      }
    ]);

    let downloadSpeed = 0;
    let uploadSpeed = 0;

    if (answer2.speedType === 'custom') {
      const custom = await inquirer.prompt([
        { type: 'number', name: 'download', message: 'Download:', default: 10 },
        { type: 'number', name: 'upload', message: 'Upload:', default: 5 }
      ]);
      downloadSpeed = custom.download;
      uploadSpeed = custom.upload;
    } else {
      downloadSpeed = Number(answer2.speedType);
      uploadSpeed = Math.round(downloadSpeed / 2);
    }

    const device = this.deviceManager.getDevice(answer1.device);
    this.bandwidthManager.setLimit(answer1.device, downloadSpeed, uploadSpeed, 'device', false);
    
    console.log();
    success(`Limit di-set!`);
    console.log(`${colors.green}   Device: ${device.name}${colors.reset}`);
    console.log(`${colors.green}   ↓ ${downloadSpeed}Mbps ↑ ${uploadSpeed}Mbps${colors.reset}`);
    console.log();
  }

  async listDevicesMenu() {
    console.log();
    const devices = this.deviceManager.getAllDevices();

    if (devices.length === 0) {
      warn('Belum ada device!');
      return;
    }

    console.log(`${colors.magenta}${colors.bold}\n📱 Device List:${colors.reset}`);
    devices.forEach((d, i) => {
      const icon = d.status === 'CONNECTED' ? '🟢' : '🔴';
      console.log(`${colors.cyan}   ${i + 1}. ${icon} ${d.name}${colors.reset}`);
      console.log(`${colors.gray}      IP: ${d.ipAddress}${colors.reset}`);
      console.log(`${colors.gray}      MAC: ${d.mac}${colors.reset}\n`);
    });
  }

  async disconnectAllMenu() {
    console.log();
    const devices = this.deviceManager.getOtherDevices();

    if (devices.length === 0) {
      warn('Tidak ada device lain!');
      return;
    }

    console.log(`${colors.magenta}${colors.bold}\nYang akan di-disconnect:${colors.reset}`);
    devices.forEach((d, i) => {
      console.log(`${colors.red}   ${i + 1}. ${d.name}${colors.reset}`);
    });

    const confirm = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'sure',
        message: `${colors.red}Yakin disconnect ${devices.length} device?${colors.reset}`,
        default: false
      }
    ]);

    if (confirm.sure) {
      console.log();
      info('Disconnecting...');

      let count = 0;
      devices.forEach(d => {
        this.deviceManager.disconnectDevice(d.mac);
        count++;
        console.log(`${colors.green}   ✅ ${d.name}${colors.reset}`);
      });

      console.log();
      success(`${count} device disconnected!`);
      console.log();
    }
  }

  async removeMenu() {
    console.log();
    const limits = this.bandwidthManager.getAllLimits();

    if (limits.length === 0) {
      warn('Tidak ada limit!');
      return;
    }

    const answer = await inquirer.prompt([
      {
        type: 'list',
        name: 'identifier',
        message: `${colors.cyan}Pilih limit untuk dihapus:${colors.reset}`,
        choices: limits.map(l => ({
          name: `${l.type === 'device' ? '📱' : '🌐'} ${l.identifier}`,
          value: l.identifier
        }))
      }
    ]);

    const confirm = await inquirer.prompt([
      { type: 'confirm', name: 'sure', message: 'Hapus?', default: false }
    ]);

    if (confirm.sure) {
      this.bandwidthManager.removeLimit(answer.identifier);
      console.log();
      success('Limit dihapus!');
      console.log();
    }
  }

  async statusMenu() {
    console.log();
    const limits = this.bandwidthManager.getAllLimits();

    if (limits.length === 0) {
      warn('Tidak ada limit!');
      return;
    }

    const answer = await inquirer.prompt([
      {
        type: 'list',
        name: 'identifier',
        message: `${colors.cyan}Pilih untuk lihat status:${colors.reset}`,
        choices: limits.map(l => ({
          name: `${l.type === 'device' ? '📱' : '🌐'} ${l.identifier}`,
          value: l.identifier
        }))
      }
    ]);

    console.log();
    info('Mengambil data...');

    const traffic = this.bandwidthManager.simulateTraffic(answer.identifier);

    console.log(`${colors.cyan}${colors.bold}\n📊 Traffic Info:${colors.reset}`);
    console.log(`${colors.gray}   ID: ${traffic.identifier}${colors.reset}`);
    console.log(`${colors.cyan}   Download: ${traffic.limitDownload}Mbps (Actual: ${traffic.actualDownload}Mbps)${colors.reset}`);
    console.log(`${colors.cyan}   Upload: ${traffic.limitUpload}Mbps (Actual: ${traffic.actualUpload}Mbps)${colors.reset}`);
    console.log(`${colors.green}   Usage: ${traffic.usagePercentage}%${colors.reset}`);
    console.log();
  }

  async speedTestMenu() {
    console.log();
    const answer = await inquirer.prompt([
      {
        type: 'list',
        name: 'type',
        message: `${colors.cyan}Test apa?${colors.reset}`,
        choices: [
          { name: '🌐 Interface', value: 'interface' },
          { name: '📱 Device', value: 'device' }
        ]
      }
    ]);

    let identifier;

    if (answer.type === 'interface') {
      const interfaces = this.networkManager.getAllInterfaces();
      const ans = await inquirer.prompt([
        {
          type: 'list',
          name: 'int',
          message: 'Pilih:',
          choices: interfaces.map(i => ({ name: i.name, value: i.name }))
        }
      ]);
      identifier = ans.int;
    } else {
      const devices = this.deviceManager.getConnectedDevices();
      if (devices.length === 0) {
        error('Tidak ada device!');
        return;
      }
      const ans = await inquirer.prompt([
        {
          type: 'list',
          name: 'dev',
          message: 'Pilih:',
          choices: devices.map(d => ({ name: d.name, value: d.mac }))
        }
      ]);
      identifier = ans.dev;
    }

    console.log();
    info('Speed test...');

    setTimeout(() => {
      const result = this.networkManager.runSpeedTest(identifier);

      console.log(`${colors.cyan}${colors.bold}\n⚡ Result:${colors.reset}`);
      console.log(`${colors.green}   ↓ ${result.downloadSpeed}Mbps${colors.reset}`);
      console.log(`${colors.green}   ↑ ${result.uploadSpeed}Mbps${colors.reset}`);
      console.log(`${colors.yellow}   Ping: ${result.ping}ms${colors.reset}`);
      console.log();
    }, 1500);
  }

  async interfacesMenu() {
    console.log();
    const interfaces = this.networkManager.getAllInterfaces();

    if (interfaces.length === 0) {
      error('Tidak ada interface!');
      return;
    }

    console.log(`${colors.magenta}${colors.bold}\n🔌 Network Interface:${colors.reset}`);
    interfaces.forEach((i, idx) => {
      console.log(`${colors.cyan}   ${idx + 1}. ${i.type}${colors.reset}`);
      console.log(`${colors.gray}      Name: ${i.name}${colors.reset}`);
      console.log(`${colors.gray}      IP: ${i.ipv4}${colors.reset}\n`);
    });
  }

  async reportMenu() {
    console.log();
    const report = this.bandwidthManager.generateReport();

    if (!report) {
      warn('Tidak ada limit!');
      return;
    }

    console.log(`${colors.magenta}${colors.bold}\n📊 Report:${colors.reset}`);
    console.log(`${colors.gray}   Total: ${report.totalLimits}${colors.reset}\n`);

    report.limits.forEach((l, i) => {
      console.log(`${colors.cyan}   ${i + 1}. ${l.type === 'device' ? '📱' : '🌐'} ${l.identifier}${colors.reset}`);
      console.log(`${colors.gray}      ↓ ${l.download}Mbps ↑ ${l.upload}Mbps${colors.reset}\n`);
    });
  }

  async askContinue() {
    const answer = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'continue',
        message: `${colors.yellow}Kembali ke menu?${colors.reset}`,
        default: true
      }
    ]);

    if (answer.continue) {
      await this.mainMenu();
    } else {
      console.log(`${colors.yellow}${colors.bold}\n👋 Selamat tinggal!\n${colors.reset}`);
      process.exit(0);
    }
  }
}

const app = new App();
app.mainMenu().catch(err => {
  error(`Error: ${err.message}`);
  process.exit(1);
});
