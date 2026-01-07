import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { getDarajaBaseUrl } from '../mpesa.config';
import { C2BRegisterUrlsDto } from '../dto/c2b-register-urls.dto';
import { C2BSimulateDto } from '../dto/c2b-simulate.dto';
import { B2CPaymentRequestDto } from '../dto/b2c-payment-request.dto';
import { B2BPaymentRequestDto } from '../dto/b2b-payment-request.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  MpesaTransaction,
  MpesaTransactionStatus,
  MpesaTransactionType,
} from '../entities/mpesa-transaction.entity';
import { Order } from 'src/order/entities/order.entity';
import { EventBusService } from 'src/queue/event-bus.service';
import {
  ORDER_PAYMENT_SUCCEEDED_EVENT,
  OrderPaymentSucceededEventPayload,
} from 'src/order/order.events';
import { FinancialStatus, OrderStatus } from 'src/order/entities/order.entity';
import { ApiClientService } from 'src/common/api-client/api-client.service';

@Injectable()
export class MpesaService {
  private readonly logger = new Logger(MpesaService.name);

  constructor(
    private readonly http: ApiClientService,
    private readonly config: ConfigService,
    private readonly eventBus: EventBusService,
    @InjectRepository(MpesaTransaction)
    private readonly mpesaTxRepo: Repository<MpesaTransaction>,
    @InjectRepository(Order)
    private readonly orderRepo: Repository<Order>,
  ) {}

  private get env(): 'sandbox' | 'production' {
    const value = this.config.get<string>('MPESA_DARAJA_ENV') ?? 'sandbox';
    return value === 'production' ? 'production' : 'sandbox';
  }

  private get baseUrl(): string {
    return getDarajaBaseUrl(this.env);
  }

  private get consumerKey(): string {
    const value = this.config.get<string>('MPESA_DARAJA_CONSUMER_KEY');
    if (!value)
      throw new BadRequestException('Missing MPESA_DARAJA_CONSUMER_KEY');
    return value;
  }

  private get consumerSecret(): string {
    const value = this.config.get<string>('MPESA_DARAJA_CONSUMER_SECRET');
    if (!value)
      throw new BadRequestException('Missing MPESA_DARAJA_CONSUMER_SECRET');
    return value;
  }

  private get shortcode(): string {
    const value = this.config.get<string>('MPESA_DARAJA_SHORTCODE');
    if (!value) throw new BadRequestException('Missing MPESA_DARAJA_SHORTCODE');
    return value;
  }

  private get initiatorName(): string {
    const value = this.config.get<string>('MPESA_DARAJA_INITIATOR_NAME');
    if (!value)
      throw new BadRequestException('Missing MPESA_DARAJA_INITIATOR_NAME');
    return value;
  }

  private get securityCredential(): string {
    const value = this.config.get<string>('MPESA_DARAJA_SECURITY_CREDENTIAL');
    if (!value)
      throw new BadRequestException('Missing MPESA_DARAJA_SECURITY_CREDENTIAL');
    return value;
  }

  private get callbackBaseUrl(): string {
    const value = this.config.get<string>('MPESA_DARAJA_CALLBACK_BASE_URL');
    if (!value)
      throw new BadRequestException('Missing MPESA_DARAJA_CALLBACK_BASE_URL');
    return value.replace(/\/$/, '');
  }

  private buildCallbackUrl(path: string): string {
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    return `${this.callbackBaseUrl}${normalizedPath}`;
  }

  private async getAccessToken(): Promise<string> {
    const basic = Buffer.from(
      `${this.consumerKey}:${this.consumerSecret}`,
    ).toString('base64');

    const url = `${this.baseUrl}/oauth/v1/generate?grant_type=client_credentials`;

    try {
      const res = await this.http.request<{ access_token?: string }>({
        operation: 'mpesa.daraja.getAccessToken',
        method: 'GET',
        url,
        headers: {
          Authorization: `Basic ${basic}`,
        },
        retry: {
          attempts: 2,
        },
      });

      const token = res.data?.access_token;
      if (!token) {
        throw new InternalServerErrorException(
          'Daraja token missing in response',
        );
      }
      return token;
    } catch (error: any) {
      const status = error?.response?.status;
      const data = error?.response?.data;
      this.logger.error(
        `Failed to get Daraja token (${status ?? 'n/a'})`,
        data,
      );
      throw new InternalServerErrorException(
        'Failed to get Daraja access token',
      );
    }
  }

  private async darajaPost<T>(path: string, payload: unknown): Promise<T> {
    const token = await this.getAccessToken();
    const url = `${this.baseUrl}${path}`;

    try {
      const res = await this.http.request<T>({
        operation: `mpesa.daraja.post${path}`,
        method: 'POST',
        url,
        data: payload,
        headers: {
          Authorization: `Bearer ${token}`,
        },
        retry: {
          // POST isn't idempotent by default; we keep attempts=1.
          attempts: 1,
        },
      });
      return res.data;
    } catch (error: any) {
      const status = error?.response?.status;
      const data = error?.response?.data;
      this.logger.error(
        `Daraja POST ${path} failed (${status ?? 'n/a'})`,
        data,
      );
      throw new InternalServerErrorException('Daraja request failed');
    }
  }

  private asStringRecord(input: unknown): Record<string, unknown> {
    if (!input || typeof input !== 'object') return {};
    return input as Record<string, unknown>;
  }

  private async linkOrderByBillRef(
    billRefNumber?: string,
  ): Promise<string | undefined> {
    if (!billRefNumber) return undefined;
    const order = await this.orderRepo.findOne({
      where: { orderNumber: billRefNumber },
    });
    return order?.id;
  }

  private async findByConversation(
    conversationId?: string,
    originatorConversationId?: string,
  ) {
    if (conversationId) {
      const found = await this.mpesaTxRepo.findOne({
        where: { conversationId },
      });
      if (found) return found;
    }
    if (originatorConversationId) {
      const found = await this.mpesaTxRepo.findOne({
        where: { originatorConversationId },
      });
      if (found) return found;
    }
    return null;
  }

  async registerC2BUrls(dto: C2BRegisterUrlsDto) {
    const shortCode = dto.shortCode || this.shortcode;

    const validationUrl =
      dto.validationUrl ??
      this.buildCallbackUrl('/api/v1/mpesa/c2b/validation');
    const confirmationUrl =
      dto.confirmationUrl ??
      this.buildCallbackUrl('/api/v1/mpesa/c2b/confirmation');

    const payload = {
      ShortCode: shortCode,
      ResponseType: dto.responseType ?? 'Completed',
      ConfirmationURL: confirmationUrl,
      ValidationURL: validationUrl,
    };

    const data = await this.darajaPost('/mpesa/c2b/v2/registerurl', payload);
    // Optionally persist for audit
    await this.mpesaTxRepo.save(
      this.mpesaTxRepo.create({
        type: MpesaTransactionType.C2B,
        status: MpesaTransactionStatus.PENDING,
        rawRequestJson: this.asStringRecord(payload),
        rawResponseJson: this.asStringRecord(data),
        rawCallbackJson: {},
      }),
    );
    return data;
  }

  async simulateC2B(dto: C2BSimulateDto) {
    const payload = {
      ShortCode: dto.shortCode,
      CommandID: dto.commandId ?? 'CustomerPayBillOnline',
      Amount: dto.amount,
      Msisdn: dto.msisdn,
      BillRefNumber: dto.billRefNumber,
    };

    const data = await this.darajaPost('/mpesa/c2b/v1/simulate', payload);
    await this.mpesaTxRepo.save(
      this.mpesaTxRepo.create({
        type: MpesaTransactionType.C2B,
        status: MpesaTransactionStatus.PENDING,
        amount: String(dto.amount),
        msisdn: dto.msisdn,
        billRefNumber: dto.billRefNumber,
        partyA: dto.shortCode,
        rawRequestJson: this.asStringRecord(payload),
        rawResponseJson: this.asStringRecord(data),
        rawCallbackJson: {},
      }),
    );
    return data;
  }

  async b2cPayment(dto: B2CPaymentRequestDto) {
    const initiatorName = dto.initiatorName ?? this.initiatorName;
    const securityCredential =
      dto.securityCredential ?? this.securityCredential;

    const payload = {
      InitiatorName: initiatorName,
      SecurityCredential: securityCredential,
      CommandID: dto.commandId ?? 'BusinessPayment',
      Amount: dto.amount,
      PartyA: dto.partyA ?? this.shortcode,
      PartyB: dto.partyB,
      Remarks: dto.remarks,
      QueueTimeOutURL:
        dto.queueTimeoutUrl ??
        this.buildCallbackUrl('/api/v1/mpesa/b2c/timeout'),
      ResultURL:
        dto.resultUrl ?? this.buildCallbackUrl('/api/v1/mpesa/b2c/result'),
      Occasion: dto.occasion ?? '',
    };

    const tx = await this.mpesaTxRepo.save(
      this.mpesaTxRepo.create({
        type: MpesaTransactionType.B2C,
        status: MpesaTransactionStatus.PENDING,
        orderId: dto.orderId,
        amount: String(dto.amount),
        partyA: String(payload.PartyA),
        partyB: dto.partyB,
        remarks: dto.remarks,
        rawRequestJson: this.asStringRecord(payload),
        rawResponseJson: {},
        rawCallbackJson: {},
      }),
    );

    const data = await this.darajaPost('/mpesa/b2c/v3/paymentrequest', payload);
    const r = this.asStringRecord(data);
    tx.originatorConversationId =
      (r.OriginatorConversationID as string) ?? tx.originatorConversationId;
    tx.conversationId = (r.ConversationID as string) ?? tx.conversationId;
    tx.resultCode =
      typeof r.ResponseCode === 'string'
        ? parseInt(r.ResponseCode, 10)
        : (r.ResponseCode as any);
    tx.resultDesc =
      (r.ResponseDescription as string) ??
      (r.ResponseDesc as string) ??
      tx.resultDesc;
    tx.rawResponseJson = r;
    await this.mpesaTxRepo.save(tx);
    return data;
  }

  async b2bPayment(dto: B2BPaymentRequestDto) {
    const initiatorName = dto.initiatorName ?? this.initiatorName;
    const securityCredential =
      dto.securityCredential ?? this.securityCredential;

    const payload = {
      Initiator: initiatorName,
      SecurityCredential: securityCredential,
      CommandID: dto.commandId ?? 'BusinessPayBill',
      Amount: dto.amount,
      PartyA: dto.partyA ?? this.shortcode,
      PartyB: dto.partyB,
      AccountReference: dto.accountReference,
      Remarks: dto.remarks,
      QueueTimeOutURL:
        dto.queueTimeoutUrl ??
        this.buildCallbackUrl('/api/v1/mpesa/b2b/timeout'),
      ResultURL:
        dto.resultUrl ?? this.buildCallbackUrl('/api/v1/mpesa/b2b/result'),
    };

    const tx = await this.mpesaTxRepo.save(
      this.mpesaTxRepo.create({
        type: MpesaTransactionType.B2B,
        status: MpesaTransactionStatus.PENDING,
        orderId: dto.orderId,
        amount: String(dto.amount),
        partyA: String(payload.PartyA),
        partyB: dto.partyB,
        accountReference: dto.accountReference,
        remarks: dto.remarks,
        rawRequestJson: this.asStringRecord(payload),
        rawResponseJson: {},
        rawCallbackJson: {},
      }),
    );

    const data = await this.darajaPost('/mpesa/b2b/v1/paymentrequest', payload);
    const r = this.asStringRecord(data);
    tx.originatorConversationId =
      (r.OriginatorConversationID as string) ?? tx.originatorConversationId;
    tx.conversationId = (r.ConversationID as string) ?? tx.conversationId;
    tx.resultCode =
      typeof r.ResponseCode === 'string'
        ? parseInt(r.ResponseCode, 10)
        : (r.ResponseCode as any);
    tx.resultDesc =
      (r.ResponseDescription as string) ??
      (r.ResponseDesc as string) ??
      tx.resultDesc;
    tx.rawResponseJson = r;
    await this.mpesaTxRepo.save(tx);
    return data;
  }

  // ---- Callback persistence helpers ----

  async handleC2BValidation(body: unknown) {
    const b = this.asStringRecord(body);
    const billRef = b.BillRefNumber as string | undefined;
    const orderId = await this.linkOrderByBillRef(billRef);

    await this.mpesaTxRepo.save(
      this.mpesaTxRepo.create({
        type: MpesaTransactionType.C2B,
        status: MpesaTransactionStatus.VALIDATION_RECEIVED,
        orderId,
        billRefNumber: billRef,
        msisdn: b.MSISDN as string,
        amount: b.TransAmount ? String(b.TransAmount) : undefined,
        transactionId: b.TransID as string,
        rawRequestJson: {},
        rawResponseJson: {},
        rawCallbackJson: b,
      }),
    );

    return { ResultCode: 0, ResultDesc: 'Accepted' };
  }

  async handleC2BConfirmation(body: unknown) {
    const b = this.asStringRecord(body);
    const billRef =
      (b.BillRefNumber as string | undefined) ?? (b.BillRefNumber as any);
    const orderId = await this.linkOrderByBillRef(billRef);

    // Upsert-ish: if a pending tx exists by transactionId, update it; else create new
    const txId = b.TransID as string | undefined;
    const existing = txId
      ? await this.mpesaTxRepo.findOne({ where: { transactionId: txId } })
      : null;

    if (existing) {
      existing.status = MpesaTransactionStatus.CONFIRMATION_RECEIVED;
      existing.orderId = existing.orderId ?? orderId;
      existing.billRefNumber = existing.billRefNumber ?? billRef;
      existing.msisdn = existing.msisdn ?? (b.MSISDN as string);
      existing.amount =
        existing.amount ?? (b.TransAmount ? String(b.TransAmount) : undefined);
      existing.rawCallbackJson = b;
      await this.mpesaTxRepo.save(existing);
    } else {
      await this.mpesaTxRepo.save(
        this.mpesaTxRepo.create({
          type: MpesaTransactionType.C2B,
          status: MpesaTransactionStatus.CONFIRMATION_RECEIVED,
          orderId,
          transactionId: txId,
          billRefNumber: billRef,
          msisdn: b.MSISDN as string,
          amount: b.TransAmount ? String(b.TransAmount) : undefined,
          rawRequestJson: {},
          rawResponseJson: {},
          rawCallbackJson: b,
        }),
      );
    }

    if (orderId) {
      // Mark order as paid/confirmed if it's not already.
      try {
        const order = await this.orderRepo.findOne({ where: { id: orderId } });
        if (order) {
          const patch: Partial<Order> = {};
          if (order.financialStatus !== FinancialStatus.PAID) {
            patch.financialStatus = FinancialStatus.PAID;
          }
          if (order.status !== OrderStatus.CONFIRMED) {
            patch.status = OrderStatus.CONFIRMED;
          }
          if (!order.confirmedAt) {
            patch.confirmedAt = new Date();
          }
          if (Object.keys(patch).length > 0) {
            await this.orderRepo.update({ id: orderId } as any, patch as any);
          }
        }
      } catch (e) {
        // Non-fatal: transaction persistence succeeded; order update can be retried.
        this.logger.warn(
          'Failed to update order status after C2B confirmation',
        );
      }

      const payload: OrderPaymentSucceededEventPayload = {
        orderId,
        msisdn: (b.MSISDN as string | undefined) ?? undefined,
        amount: b.TransAmount ? String(b.TransAmount) : undefined,
        transactionId: (b.TransID as string | undefined) ?? undefined,
      };

      await this.eventBus.emit<OrderPaymentSucceededEventPayload>(
        ORDER_PAYMENT_SUCCEEDED_EVENT,
        payload,
      );
    }

    return { ResultCode: 0, ResultDesc: 'Received' };
  }

  private parseResultEnvelope(body: unknown): {
    conversationId?: string;
    originatorConversationId?: string;
    resultCode?: number;
    resultDesc?: string;
    transactionId?: string;
    raw: Record<string, unknown>;
  } {
    const raw = this.asStringRecord(body);
    const result = this.asStringRecord(raw.Result);

    const conversationId = result.ConversationID as string | undefined;
    const originatorConversationId = result.OriginatorConversationID as
      | string
      | undefined;
    const resultCode =
      typeof result.ResultCode === 'number'
        ? result.ResultCode
        : typeof result.ResultCode === 'string'
          ? parseInt(result.ResultCode, 10)
          : undefined;
    const resultDesc = result.ResultDesc as string | undefined;

    // Transaction ID sometimes appears in ResultParameters
    let transactionId: string | undefined;
    const params = this.asStringRecord(result.ResultParameters);
    const arr = params.ResultParameter as unknown[];
    if (Array.isArray(arr)) {
      for (const p of arr) {
        const pr = this.asStringRecord(p);
        if (pr.Key === 'TransactionID' && typeof pr.Value === 'string') {
          transactionId = pr.Value;
        }
      }
    }

    return {
      conversationId,
      originatorConversationId,
      resultCode,
      resultDesc,
      transactionId,
      raw,
    };
  }

  async handleB2CResult(body: unknown) {
    const parsed = this.parseResultEnvelope(body);
    const existing = await this.findByConversation(
      parsed.conversationId,
      parsed.originatorConversationId,
    );

    if (existing) {
      existing.resultCode = parsed.resultCode;
      existing.resultDesc = parsed.resultDesc;
      existing.transactionId = parsed.transactionId ?? existing.transactionId;
      existing.status =
        parsed.resultCode === 0
          ? MpesaTransactionStatus.SUCCESS
          : MpesaTransactionStatus.FAILED;
      existing.rawCallbackJson = parsed.raw;
      await this.mpesaTxRepo.save(existing);
    } else {
      await this.mpesaTxRepo.save(
        this.mpesaTxRepo.create({
          type: MpesaTransactionType.B2C,
          status:
            parsed.resultCode === 0
              ? MpesaTransactionStatus.SUCCESS
              : MpesaTransactionStatus.FAILED,
          conversationId: parsed.conversationId,
          originatorConversationId: parsed.originatorConversationId,
          transactionId: parsed.transactionId,
          resultCode: parsed.resultCode,
          resultDesc: parsed.resultDesc,
          rawRequestJson: {},
          rawResponseJson: {},
          rawCallbackJson: parsed.raw,
        }),
      );
    }

    return { ResultCode: 0, ResultDesc: 'Received' };
  }

  async handleB2CTimeout(body: unknown) {
    const parsed = this.parseResultEnvelope(body);
    const existing = await this.findByConversation(
      parsed.conversationId,
      parsed.originatorConversationId,
    );
    if (existing) {
      existing.status = MpesaTransactionStatus.TIMEOUT;
      existing.rawCallbackJson = parsed.raw;
      await this.mpesaTxRepo.save(existing);
    } else {
      await this.mpesaTxRepo.save(
        this.mpesaTxRepo.create({
          type: MpesaTransactionType.B2C,
          status: MpesaTransactionStatus.TIMEOUT,
          conversationId: parsed.conversationId,
          originatorConversationId: parsed.originatorConversationId,
          rawRequestJson: {},
          rawResponseJson: {},
          rawCallbackJson: parsed.raw,
        }),
      );
    }
    return { ResultCode: 0, ResultDesc: 'Received' };
  }

  async handleB2BResult(body: unknown) {
    const parsed = this.parseResultEnvelope(body);
    const existing = await this.findByConversation(
      parsed.conversationId,
      parsed.originatorConversationId,
    );

    if (existing) {
      existing.resultCode = parsed.resultCode;
      existing.resultDesc = parsed.resultDesc;
      existing.transactionId = parsed.transactionId ?? existing.transactionId;
      existing.status =
        parsed.resultCode === 0
          ? MpesaTransactionStatus.SUCCESS
          : MpesaTransactionStatus.FAILED;
      existing.rawCallbackJson = parsed.raw;
      await this.mpesaTxRepo.save(existing);
    } else {
      await this.mpesaTxRepo.save(
        this.mpesaTxRepo.create({
          type: MpesaTransactionType.B2B,
          status:
            parsed.resultCode === 0
              ? MpesaTransactionStatus.SUCCESS
              : MpesaTransactionStatus.FAILED,
          conversationId: parsed.conversationId,
          originatorConversationId: parsed.originatorConversationId,
          transactionId: parsed.transactionId,
          resultCode: parsed.resultCode,
          resultDesc: parsed.resultDesc,
          rawRequestJson: {},
          rawResponseJson: {},
          rawCallbackJson: parsed.raw,
        }),
      );
    }

    return { ResultCode: 0, ResultDesc: 'Received' };
  }

  async handleB2BTimeout(body: unknown) {
    const parsed = this.parseResultEnvelope(body);
    const existing = await this.findByConversation(
      parsed.conversationId,
      parsed.originatorConversationId,
    );
    if (existing) {
      existing.status = MpesaTransactionStatus.TIMEOUT;
      existing.rawCallbackJson = parsed.raw;
      await this.mpesaTxRepo.save(existing);
    } else {
      await this.mpesaTxRepo.save(
        this.mpesaTxRepo.create({
          type: MpesaTransactionType.B2B,
          status: MpesaTransactionStatus.TIMEOUT,
          conversationId: parsed.conversationId,
          originatorConversationId: parsed.originatorConversationId,
          rawRequestJson: {},
          rawResponseJson: {},
          rawCallbackJson: parsed.raw,
        }),
      );
    }
    return { ResultCode: 0, ResultDesc: 'Received' };
  }
}
