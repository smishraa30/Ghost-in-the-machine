const fs = require('fs');
const path = require('path');

const srcDir = path.join(__dirname, 'Ghost-in-the-machine-dashboard', 'dist');
const destDir = path.join(__dirname, 'public');

function copyFile(src, dest) {
  fs.copyFileSync(src, dest);
  console.log(`[Copy] ${path.basename(src)} -> ${dest}`);
}

function copyFolderSync(from, to) {
  if (!fs.existsSync(to)) {
    fs.mkdirSync(to, { recursive: true });
  }
  fs.readdirSync(from).forEach(element => {
    const fromPath = path.join(from, element);
    const toPath = path.join(to, element);
    if (fs.lstatSync(fromPath).isDirectory()) {
      copyFolderSync(fromPath, toPath);
    } else {
      fs.copyFileSync(fromPath, toPath);
      console.log(`[Copy] Asset: ${element} -> ${toPath}`);
    }
  });
}

console.log('Starting asset copy process...');

if (!fs.existsSync(srcDir)) {
  console.error(`Error: Source directory ${srcDir} does not exist. Did you run npm run build in the dashboard folder?`);
  process.exit(1);
}

// Copy HTML files
copyFile(path.join(srcDir, 'index.html'), path.join(destDir, 'landing.html'));
const distDashboard = path.join(srcDir, 'dashboard.html');
if (fs.existsSync(distDashboard)) {
  copyFile(distDashboard, path.join(destDir, 'dashboard.html'));
} else {
  console.log('[Copy] Skipping dashboard.html as it does not exist in dist (serving from public/).');
}

// Copy Assets folder
const srcAssets = path.join(srcDir, 'assets');
const destAssets = path.join(destDir, 'assets');

if (fs.existsSync(srcAssets)) {
  // Clear dest assets first to avoid cluttering with old builds
  if (fs.existsSync(destAssets)) {
    fs.rmSync(destAssets, { recursive: true, force: true });
  }
  copyFolderSync(srcAssets, destAssets);
} else {
  console.warn('Warning: No assets folder found in dist.');
}

console.log('Asset copy process completed successfully.');
