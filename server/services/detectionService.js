import { spawn } from 'child_process';
import config from '../config.js';

export function analyzeLogFile() {
  return new Promise((resolve, reject) => {
    const child = spawn(config.pythonExecutable, [config.pythonScriptPath, '--logfile', config.logPath]);
    let output = '';
    let errorOutput = '';

    child.stdout.on('data', (chunk) => { output += chunk.toString(); });
    child.stderr.on('data', (chunk) => { errorOutput += chunk.toString(); });

    child.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(`Detection engine exited with code ${code}: ${errorOutput}`));
      }
      try {
        const alerts = JSON.parse(output || '[]');
        resolve(alerts);
      } catch (err) {
        reject(new Error(`Invalid detection output: ${err.message}`));
      }
    });
  });
}
