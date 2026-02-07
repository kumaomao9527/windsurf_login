import * as vscode from 'vscode';

const PLAN_STATUS_URL = 'https://web-backend.windsurf.com/exa.seat_management_pb.SeatManagementService/GetPlanStatus';

export interface UsageInfo {
    planName: string;
    userPromptCredits: {
        used: number;
        total: number;
        left: number;
    };
    addOnCredits: {
        used: number;
        total: number;
        left: number;
    };
    usageSince?: string;
    expiresAt?: number;  // 订阅到期时间戳（毫秒）
    remainingDays?: number;  // 剩余天数
}

/**
 * Windsurf 账号切换器
 */
export class WindsurfInjector {
    private logger: vscode.OutputChannel;

    constructor() {
        this.logger = vscode.window.createOutputChannel('Windsurf Login');
    }

    /**
     * 切换账号
     * @param apiKey idToken/accessToken
     * @param name 账号名称
     */
    public async switchAccount(apiKey: string, name: string): Promise<{ success: boolean; error?: string }> {
        try {
            this.log(`[切换账号] ${name}`);

            if (!apiKey) {
                return { success: false, error: 'apiKey 不能为空' };
            }

            await vscode.commands.executeCommand('windsurf.provideAuthTokenToAuthProvider', apiKey);
            this.log(`[切换账号] ✓ 成功: ${name}`);
            return { success: true };
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.log(`[切换账号] ✗ 失败: ${message}`);
            return { success: false, error: message };
        }
    }

    /**
     * 显示日志
     */
    public showLog(): void {
        this.logger.show();
    }

    /**
     * 写入日志
     */
    public log(message: string): void {
        this.logger.appendLine(`[${new Date().toLocaleTimeString()}] ${message}`);
    }

    /**
     * 获取用量信息
     * @param idToken Firebase ID Token
     */
    public async getUsage(idToken: string): Promise<UsageInfo | null> {
        try {
            // 构建 protobuf 请求体: field 1 (string) = idToken, field 2 (int32) = 1
            const tokenBytes = new TextEncoder().encode(idToken);
            const lengthVarint = this.encodeVarint(tokenBytes.length);
            const requestBody = new Uint8Array(1 + lengthVarint.length + tokenBytes.length + 2);
            let offset = 0;
            requestBody[offset++] = 0x0a; // field 1, wire type 2 (length-delimited)
            requestBody.set(lengthVarint, offset);
            offset += lengthVarint.length;
            requestBody.set(tokenBytes, offset);
            offset += tokenBytes.length;
            requestBody[offset++] = 0x10; // field 2, wire type 0 (varint)
            requestBody[offset] = 0x01; // value = 1

            const response = await fetch(PLAN_STATUS_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/proto',
                    'x-auth-token': idToken,
                    'connect-protocol-version': '1'
                },
                body: requestBody
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const buffer = await response.arrayBuffer();
            const data = new Uint8Array(buffer);
            
            // 解析响应
            const usage = this.parseUsageResponse(data);
            this.log(`[查询用量] ✓ ${usage.planName} - ${usage.userPromptCredits.left}/${usage.userPromptCredits.total} credits`);
            return usage;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.log(`[查询用量] ✗ 失败: ${message}`);
            return null;
        }
    }

    /**
     * 解析用量响应 (简化的 protobuf 解析)
     */
    private parseUsageResponse(data: Uint8Array): UsageInfo {
        // 解析 planName - 查找 field 2 (tag 0x12)
        let planName = 'Unknown';
        for (let i = 0; i < data.length - 2; i++) {
            if (data[i] === 0x12) { // field 2, wire type 2 (length-delimited)
                const len = data[i + 1];
                if (len > 0 && len < 50 && i + 2 + len <= data.length) {
                    const nameBytes = data.slice(i + 2, i + 2 + len);
                    const name = new TextDecoder().decode(nameBytes);
                    if (/^[A-Za-z]+$/.test(name)) {
                        planName = name;
                        break;
                    }
                }
            }
        }

        // 根据 protobuf 响应分析:
        // Free 计划响应: 40 64 (field 8 = 100), 显示 25 credits
        // Trial 计划响应: 40 d8 04 (field 8 = 600), 显示 100 credits
        // 结论: field 8 是总 credits 池, 实际 prompt credits = field 8 / 4 (Free) 或其他计算
        // 
        // 更准确的分析:
        // - field 8 (0x40): 总 credits 池
        // - field 12 (0x60): 某个大数值 (10000 for Trial, 2500 for Free)
        // - field 13 (0x68): 已使用或剩余的某个值
        //
        // 根据网页显示，需要找到正确的 total 和 left 字段
        // Trial: 84/100 prompt credits left
        // Free: 25/25 prompt credits left
        
        let total = 0;
        let left = 0;
        let field8Value = 0;
        let field12Value = 0;
        let field13Value = 0;

        // 扫描所有 varint 字段
        for (let i = 0; i < data.length - 1; i++) {
            const tag = data[i];
            const fieldNum = tag >> 3;
            const wireType = tag & 0x07;
            
            if (wireType === 0 && fieldNum > 0) { // varint field
                const result = this.readVarint(data, i + 1);
                
                if (fieldNum === 8 && field8Value === 0) {
                    field8Value = result.value;
                } else if (fieldNum === 12 && field12Value === 0) {
                    field12Value = result.value;
                } else if (fieldNum === 13 && field13Value === 0) {
                    field13Value = result.value;
                }
            }
        }

        // 响应末尾有汇总数据: 30 xx (field 6 = used*100), 40 xx (field 8 = total*100)
        // 需要从响应末尾提取这些字段
        let endField6 = 0; // used * 100
        let endField8 = 0; // total * 100
        
        // 从响应末尾向前扫描，查找最后出现的 field 6 和 field 8
        for (let i = data.length - 20; i < data.length - 1; i++) {
            if (i < 0) continue;
            const tag = data[i];
            const fieldNum = tag >> 3;
            const wireType = tag & 0x07;
            
            if (wireType === 0) {
                const result = this.readVarint(data, i + 1);
                if (fieldNum === 6 && result.value > 0) {
                    endField6 = result.value;
                } else if (fieldNum === 8 && result.value > 0) {
                    endField8 = result.value;
                }
            }
        }

        // 计算公式 (基于响应末尾的汇总数据):
        // - total = endField8 / 100
        // - used = endField6 / 100
        // - left = total - used
        if (endField8 > 0) {
            total = Math.round(endField8 / 100);
            const used = endField6 > 0 ? Math.round(endField6 / 100) : 0;
            left = total - used;
        } else if (field12Value > 0) {
            // 备用: 使用内层消息的 field 12
            total = Math.round(field12Value / 100);
            left = total; // 假设未使用
        } else if (field8Value > 0) {
            // 再备用: 使用内层消息的 field 8
            total = Math.round(field8Value / 4);
            left = total;
        }

        const used = total - left;

        // 查找订阅到期时间戳（通常是 10 位秒级时间戳，值在 1700000000-2000000000 范围内）
        let expiresAt: number | undefined;
        let remainingDays: number | undefined;
        
        // 扫描所有 varint 字段，查找时间戳
        const timestamps: number[] = [];
        for (let i = 0; i < data.length - 1; i++) {
            const tag = data[i];
            const fieldNum = tag >> 3;
            const wireType = tag & 0x07;
            
            if (wireType === 0 && fieldNum > 0) {
                const result = this.readVarint(data, i + 1);
                // 检查是否是合理的时间戳（2024-2030年范围）
                if (result.value >= 1704067200 && result.value <= 1893456000) {
                    timestamps.push(result.value);
                }
            }
        }

        // 选择最大的时间戳作为到期时间（通常到期时间是未来的日期）
        if (timestamps.length > 0) {
            const maxTimestamp = Math.max(...timestamps);
            expiresAt = maxTimestamp * 1000; // 转换为毫秒
            const now = Date.now();
            if (expiresAt > now) {
                remainingDays = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
            }
        }

        return {
            planName,
            userPromptCredits: { used, total, left },
            addOnCredits: { used: 0, total: 0, left: 0 },
            usageSince: new Date().toLocaleDateString(),
            expiresAt,
            remainingDays
        };
    }

    /**
     * 编码 varint
     */
    private encodeVarint(value: number): Uint8Array {
        const bytes: number[] = [];
        while (value > 0x7f) {
            bytes.push((value & 0x7f) | 0x80);
            value >>>= 7;
        }
        bytes.push(value);
        return new Uint8Array(bytes);
    }

    /**
     * 读取 varint
     */
    private readVarint(data: Uint8Array, offset: number): { value: number; bytesRead: number } {
        let value = 0;
        let shift = 0;
        let bytesRead = 0;

        while (offset + bytesRead < data.length) {
            const byte = data[offset + bytesRead];
            value |= (byte & 0x7f) << shift;
            bytesRead++;
            if ((byte & 0x80) === 0) {
                break;
            }
            shift += 7;
        }

        return { value, bytesRead };
    }
}
