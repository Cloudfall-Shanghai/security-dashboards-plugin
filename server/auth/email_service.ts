/*
 *   Copyright OpenSearch Contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

import { SecurityPluginConfigType } from "..";

// import nodemailer from 'nodemailer';
import nodemailer from 'nodemailer';

export interface EmailConfig {
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    sender_email: string;
    sender_password: string;
  };
  email: {
    from: string;
    subject: string;
    codeExpireMinutes: number;
  };
  verification: {
    codeLength: number;
    maxAttempts: number;
  };
  rateLimit: {
    maxRequests: number;
    windowMinutes: number; // 1 分钟
  };
}

export class EmailService {
  private static instance: EmailService;
  private transporter!: nodemailer.Transporter;
  private verificationCodes: Map<string, { code: string; timestamp: number; attempts: number }>;
  private config: EmailConfig;

  private constructor(config: EmailConfig) {
    // this.validateConfig(config);
    this.config = config;
    this.verificationCodes = new Map();
    this.initializeTransporter();
  }

  private validateConfig(config: EmailConfig): void {
    const errors: string[] = [];

    if (!config.smtp.host) errors.push('SMTP host is required');
    if (!config.smtp.port) errors.push('SMTP port is required');
    if (!config.email.from) errors.push('Sender email is required');
    if (config.verification.codeLength < 4 || config.verification.codeLength > 8) {
      errors.push('Code length must be between 4 and 8');
    }

    if (errors.length > 0) {
      throw new Error(`Invalid MFA configuration: ${errors.join(', ')}`);
    }
  }

  private initializeTransporter(): void {
    this.transporter = nodemailer.createTransport({
      host: this.config.smtp.host,
      port: this.config.smtp.port,
      secure: this.config.smtp.secure,
      auth: {
        user: this.config.smtp.sender_email,
        pass: this.config.smtp.sender_password
      },
      tls: {
        rejectUnauthorized: false
      }
    });
  }

  public static getInstance(config?: EmailConfig): EmailService {
    if (!EmailService.instance) {
      EmailService.instance = new EmailService(config as unknown as EmailConfig);
    }
    return EmailService.instance;
  }

  private generateVerificationCode(): string {
    const digits = this.config.verification.codeLength;
    let code = '';
    for (let i = 0; i < digits; i++) {
      code += Math.floor(Math.random() * 10).toString();
    }
    return code;
  }

  public async sendVerificationCode(email: string): Promise<string> {
    // Check rate limit
    const now = Date.now();
    const codeData = this.verificationCodes.get(email);

    if (codeData && (now - codeData.timestamp) < this.config.rateLimit.windowMinutes * 60000) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }

    const code = this.generateVerificationCode();
    const mailContent = `
    <div style="margin: 0 10% 0 10%;">
    <table border="0" style="border-collapse: collapse; font-size: 14px;margin-top: -18px;">
        <thead>
            <tr>
                <td width="500px">
                    <h1 style="margin-top: 20px;">Verify your email</h1>
                </td>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td width="500px">
                    <p style="margin-top: 20px;">We need to verify your email address ${email} before you can access your account. Enter the code below in your open browser window.</p>
                </td>
            </tr>
            <tr>
                <td width="500px">
                    <h1 style="margin-top: 20px;">${code}</h1>
                </td>
            </tr>
            <tr>
                <td width="500px">
                    <p style="color: gray;font-size: 12px;">This code expires in ${this.config.email.codeExpireMinutes} minutes.</p>
                </td>
            </tr>
        </tbody>
    </table>
    <br>
    <p style="color: gray;font-size: 12px;">This email is sent automatically, please do not reply.</p>
</div>
    `

    try {
      await this.transporter.sendMail({
        from: this.config.email.from,
        to: email,
        subject: this.config.email.subject,
        html: mailContent
      });

      this.verificationCodes.set(email, {
        code,
        timestamp: now,
        attempts: 0
      });

      return code;
    } catch (error) {
      console.error('Failed to send verification code');
      console.error({ error });
      throw new Error('Failed to send verification code');
    }
  }

  public verifyCode(email: string, code: string): { success: boolean, message?: string } {
    // 清理过期的验证码
    this.cleanupExpiredCodes();

    const data = this.verificationCodes.get(email);
    if (!data) return {
      success: false,
      message: 'Verification session expired, please login again.'
    };

    data.attempts++;
    if (data.attempts > this.config.verification.maxAttempts) {
      this.verificationCodes.delete(email);
      return {
        success: false,
        message: 'Maximum verification attempts exceeded.'
      }
    }

    const isValid = data.code === code &&
      (Date.now() - data.timestamp) <= this.config.email.codeExpireMinutes * 60000;

    if (isValid) {
      this.verificationCodes.delete(email);
    }

    return {
      success: isValid,
      message: isValid ? undefined : 'Invalid verification code or email address.'
    };
  }

  /**
   * 清理过期的验证码
   */
  public cleanupExpiredCodes(): void {
    const now = Date.now();
    for (const [email, data] of this.verificationCodes.entries()) {
      if (now - data.timestamp > this.config.email.codeExpireMinutes * 60000) {
        this.verificationCodes.delete(email);
      }
    }
  }
}
