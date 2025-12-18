import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Order } from '../entities/order.entity';
import { OrderItem } from '../entities/order-item.entity';
import { OrderLevelCharge } from '../entities/order-level-charge.entity';
import { CreateOrderDto } from '../dto/create-order.dto';
import { PriceService } from '../../catalog/services/price.service';
import { PromotionService } from '../../promotion/services/promotion.service';
import { ProductVariant } from '../../catalog/entities/product-variant.entity';
import { PriceList } from '../../catalog/entities/price-list.entity';
import { TaxService } from './tax.service';
import { ShippingMatrixService } from '../../shipping/services/shipping-matrix.service';

@Injectable()
export class OrderService {
  constructor(
    @InjectRepository(Order)
    private readonly orderRepository: Repository<Order>,
    @InjectRepository(OrderItem)
    private readonly orderItemRepository: Repository<OrderItem>,
    @InjectRepository(ProductVariant)
    private readonly productVariantRepository: Repository<ProductVariant>,
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(OrderLevelCharge)
    private readonly orderLevelChargeRepository: Repository<OrderLevelCharge>,
    private readonly priceService: PriceService,
    private readonly promotionService: PromotionService,
    private readonly shippingMatrixService: ShippingMatrixService,
    private readonly taxService: TaxService,
  ) {}

  async create(payload: CreateOrderDto) {
    // Resolve price list if provided
    let priceList: PriceList | null = null;
    if (payload.priceListId) {
      priceList = await this.priceListRepository.findOne({ where: { id: payload.priceListId } });
      if (!priceList) {
        throw new NotFoundException('Price list not found');
      }
    }

    const order = this.orderRepository.create({
      orderNumber: await this.generateOrderNumber(),
      customerEmail: payload.customerEmail,
      customerName: payload.customerName,
      priceListId: priceList?.id ?? (await this.priceService.findActivePriceListByCurrency('KES'))?.id,
      currencyCode: priceList?.currencyCode ?? (await this.priceService.findActivePriceListByCurrency('KES'))?.currencyCode,
      itemsSubtotal: '0',
      discountTotal: '0',
      feeTotal: '0',
      taxTotal: '0',
      shippingSubtotal: '0',
      shippingDiscount: '0',
      shippingTax: '0',
      shippingTotal: '0',
      grandTotal: '0',
      itemCount: 0,
      metaJson: {},
    });

    const savedOrder = await this.orderRepository.save(order);

    let itemsSubtotal = 0;
    let totalItemCount = 0;

    for (const item of payload.items) {
      const variant = await this.productVariantRepository.findOne({ where: { id: item.productVariantId } });
      if (!variant) {
        throw new NotFoundException('Product variant not found');
      }

      const resolved = await this.priceService.resolveVariantPrice({
        productVariantId: item.productVariantId,
        priceListId: priceList?.id,
        quantity: item.quantity,
      });

      const unitPrice = parseFloat(resolved.unitPrice);
      const baseSubtotal = unitPrice * item.quantity;

      itemsSubtotal += baseSubtotal;
      totalItemCount += item.quantity;

      const orderItem = this.orderItemRepository.create({
        orderId: savedOrder.id,
        productVariantId: variant.id,
        sku: variant.sku,
        productName: variant.title,
        variantTitle: variant.title,
        variantOptionsJson: {},
        attributesJson: {},
        quantity: item.quantity,
        priceListId: resolved.priceListId,
        unitPrice: resolved.unitPrice,
        compareAtPrice: resolved.compareAtPrice,
        baseSubtotal: baseSubtotal.toFixed(4),
        discountTotal: '0',
        feeTotal: '0',
        taxTotal: '0',
        total: baseSubtotal.toFixed(4),
        requiresShipping: variant.requiresShipping,
        fulfillmentStatus: 'unfulfilled',
        pricingSnapshotJson: { resolved },
        // Persist the variant weight so later total weight calculation can read it from the order item
        metaJson: { weight: variant.weight },
      });

      await this.orderItemRepository.save(orderItem);
    }

    savedOrder.itemsSubtotal = itemsSubtotal.toFixed(4);
    savedOrder.itemCount = totalItemCount;

    // Evaluate promotions and apply discounts (simple order-level promotion evaluation)
    const promoResult = await this.promotionService.evaluatePromotions({
      subtotal: savedOrder.itemsSubtotal,
      currencyCode: savedOrder.currencyCode,
    });

    const totalDiscount = Number(promoResult.totalDiscount || '0');

    if (totalDiscount > 0) {
      // Persist an order-level charge representing the promotion discount
      const charge = this.orderLevelChargeRepository.create({
        orderId: savedOrder.id,
        chargeKind: 'discount',
        code: promoResult.applied.map((a) => a.code).join(','),
        displayName: 'Promotion Discount',
        calculationType: 'fixed',
        baseAmount: savedOrder.itemsSubtotal,
        amount: (-totalDiscount).toFixed(4),
        isIncludedInPrice: false,
        appliesToShipping: false,
        sourceType: 'promotion',
        sourceReference: promoResult.applied.map((a) => a.promotionId).join(','),
        metaJson: { applied: promoResult.applied },
      });
      await this.orderLevelChargeRepository.save(charge);
    }

    savedOrder.discountTotal = totalDiscount.toFixed(2);

    // Shipping calculation using the ShippingMatrixService (select best candidate)
    const activePromos = await this.promotionService.findActivePromotions(savedOrder.currencyCode);
    const hasFreeShipping = activePromos.some((p) => p.type === 'free_shipping');

    // compute total weight from items (attempt to use variant.weight if set)
    let totalWeight = 0;
    try {
      const items = await this.orderItemRepository.find({ where: { orderId: savedOrder.id } });
      for (const it of items) {
        // pricingSnapshotJson.resolved may contain variant metadata but we conservatively attempt to read numeric weight from meta
        const weight = Number((it as any).weight || (it as any).metaJson?.weight || 0);
        totalWeight += (it.quantity || 0) * (weight || 0);
      }
    } catch (e) {
      // ignore and allow 0 weight
    }

    const quotes = await this.shippingMatrixService.getQuotes({
      countryCode: (payload as any).shippingCountry || undefined,
      region: (payload as any).shippingRegion || undefined,
      postalCode: (payload as any).shippingPostalCode || undefined,
      subtotal: itemsSubtotal,
      totalWeight,
      itemCount: totalItemCount,
      currencyCode: savedOrder.currencyCode,
    });

    const best = quotes[0];
    const shippingFee = best ? best.amount : 0;

    if (shippingFee !== 0) {
      const shippingCharge = this.orderLevelChargeRepository.create({
        orderId: savedOrder.id,
        chargeKind: 'shipping',
        displayName: best ? best.method.displayName : 'Shipping',
        calculationType: best ? best.rate.calculationType : 'fixed',
        baseAmount: savedOrder.itemsSubtotal,
        amount: shippingFee.toFixed(4),
        isIncludedInPrice: false,
        appliesToShipping: true,
        sourceType: 'shipping',
        sourceReference: best ? best.method.code : undefined,
        metaJson: best ? { methodId: best.method.id, rateId: best.rate.id, meta: best.rate.metaJson } : {},
      });
      await this.orderLevelChargeRepository.save(shippingCharge);
    }

    savedOrder.shippingSubtotal = shippingFee.toFixed(4);

    // Tax calculation using TaxService for configurable tax rate
    const taxable = itemsSubtotal - totalDiscount + shippingFee;
    const taxResult = await this.taxService.calculateTax({ taxableAmount: taxable, currencyCode: savedOrder.currencyCode });

    const taxAmount = taxResult.amount;

    const taxCharge = this.orderLevelChargeRepository.create({
      orderId: savedOrder.id,
      chargeKind: 'tax',
      displayName: 'Tax',
      calculationType: taxResult.rate ? 'percentage' : 'fixed',
      rate: (taxResult.rate || 0).toFixed(6) as any,
      baseAmount: taxable.toFixed(4),
      amount: taxAmount.toFixed(4),
      isIncludedInPrice: false,
      appliesToShipping: false,
      sourceType: 'tax',
      metaJson: taxResult.meta || {},
    });

    await this.orderLevelChargeRepository.save(taxCharge);

    savedOrder.taxTotal = taxAmount.toFixed(4);
    savedOrder.shippingTax = taxAmount.toFixed(4); // for clarity keep the same value under shippingTax
    savedOrder.shippingTotal = (shippingFee + taxAmount).toFixed(4);

    // Grand total: itemsSubtotal - discounts + shipping + tax
    savedOrder.grandTotal = (itemsSubtotal - totalDiscount + shippingFee + taxAmount).toFixed(4);

    const updated = await this.orderRepository.save(savedOrder);
    return updated;
  }

  private async generateOrderNumber() {
    // Simple generator for now, in real system use a robust sequence
    const seq = Math.floor(Math.random() * 1000000);
    return `ORD-${Date.now()}-${seq}`;
  }
}
