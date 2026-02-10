import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';

/**
 * Windsurf 机器码重置器
 */
export class MachineIdResetter {
    private logger: vscode.OutputChannel;

    constructor() {
        this.logger = vscode.window.createOutputChannel('Windsurf Machine ID Resetter');
    }

    /**
     * 获取 Windsurf 配置目录路径
     */
    private getWindsurfPath(): string {
        const home = process.env.HOME || '';
        if (process.platform === 'win32') {
            return path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Windsurf');
        } else if (process.platform === 'darwin') {
            return path.join(home, 'Library', 'Application Support', 'Windsurf');
        } else {
            // Linux
            return path.join(home, '.config', 'Windsurf');
        }
    }

    /**
     * 重置 Windsurf 机器码
     */
    public async resetMachineId(): Promise<{ success: boolean; error?: string; newMachineId?: string }> {
        try {
            this.logger.appendLine(`[${new Date().toLocaleTimeString()}] 开始重置机器码...`);

            const windsurfPath = this.getWindsurfPath();
            if (!fs.existsSync(windsurfPath)) {
                throw new Error(`Windsurf 目录不存在: ${windsurfPath}`);
            }

            // 生成新的机器码 (UUID v4)
            const newMachineId = randomUUID();
            this.logger.appendLine(`生成新机器码: ${newMachineId}`);

            // 定义需要更新的文件路径
            const filesToUpdate: { path: string; content: string; description: string }[] = [
                {
                    path: path.join(windsurfPath, 'machineid'),
                    content: newMachineId,
                    description: 'machineid'
                },
                {
                    path: path.join(windsurfPath, 'machineid.json'),
                    content: JSON.stringify({ machineId: newMachineId }, null, 2),
                    description: 'machineid.json'
                },
                {
                    path: path.join(windsurfPath, 'User', 'globalStorage', 'machine-id'),
                    content: newMachineId,
                    description: 'globalStorage/machine-id'
                }
            ];

            // 尝试更新 storage.json 中的 telemetry.machineId
            const storageJsonPath = path.join(windsurfPath, 'User', 'globalStorage', 'storage.json');
            if (fs.existsSync(storageJsonPath)) {
                try {
                    const storage = JSON.parse(fs.readFileSync(storageJsonPath, 'utf-8'));
                    if (storage['telemetry.machineId']) {
                        storage['telemetry.machineId'] = newMachineId;
                        filesToUpdate.push({
                            path: storageJsonPath,
                            content: JSON.stringify(storage, null, 2),
                            description: 'User/globalStorage/storage.json'
                        });
                        this.logger.appendLine(`添加 storage.json 到更新队列`);
                    }
                } catch (e) {
                    this.logger.appendLine(`解析 storage.json 失败: ${e}`);
                }
            }

            // 备份旧的机器码
            const backupDir = path.join(windsurfPath, 'machine-id-backups');
            if (!fs.existsSync(backupDir)) {
                fs.mkdirSync(backupDir, { recursive: true });
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            
            // 更新所有文件
            for (const file of filesToUpdate) {
                try {
                    // 备份旧文件
                    if (fs.existsSync(file.path)) {
                        const oldContent = fs.readFileSync(file.path, 'utf-8');
                        const backupPath = path.join(backupDir, `${path.basename(file.path)}.backup_${timestamp}`);
                        fs.writeFileSync(backupPath, oldContent, 'utf-8');
                        this.logger.appendLine(`✓ 备份 ${file.description} -> ${backupPath}`);
                    }

                    // 写入新机器码
                    const dir = path.dirname(file.path);
                    if (!fs.existsSync(dir)) {
                        fs.mkdirSync(dir, { recursive: true });
                    }
                    fs.writeFileSync(file.path, file.content, 'utf-8');
                    this.logger.appendLine(`✓ 更新 ${file.description}`);
                } catch (error) {
                    const message = error instanceof Error ? error.message : String(error);
                    this.logger.appendLine(`⚠ 更新 ${file.description} 失败: ${message}`);
                }
            }

            this.logger.appendLine(`✓ 机器码重置成功: ${newMachineId}`);
            this.logger.appendLine(`提示: 请重启 Windsurf 使更改生效`);
            
            return { success: true, newMachineId };
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger.appendLine(`✗ 机器码重置失败: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * 获取当前机器码
     */
    public getCurrentMachineId(): string | null {
        try {
            const windsurfPath = this.getWindsurfPath();
            const machineIdPath = path.join(windsurfPath, 'machineid');
            if (fs.existsSync(machineIdPath)) {
                return fs.readFileSync(machineIdPath, 'utf-8').trim();
            }
            return null;
        } catch {
            return null;
        }
    }

    /**
     * 显示日志
     */
    public showLog(): void {
        this.logger.show();
    }
}

