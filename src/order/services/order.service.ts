import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Order } from '../entities/order.entity';
import { OrderItem } from '../entities/order-item.entity';
import { CreateOrderDto } from '../dto/create-order.dto';
import { PriceService } from '../../catalog/services/price.service';
import { ProductVariant } from '../../catalog/entities/product-variant.entity';
import { PriceList } from '../../catalog/entities/price-list.entity';

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
    private readonly priceService: PriceService,
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
        metaJson: {},
      });

      await this.orderItemRepository.save(orderItem);
    }

    savedOrder.itemsSubtotal = itemsSubtotal.toFixed(4);
    savedOrder.itemCount = totalItemCount;
    savedOrder.grandTotal = itemsSubtotal.toFixed(4);

    const updated = await this.orderRepository.save(savedOrder);
    return updated;
  }

  private async generateOrderNumber() {
    // Simple generator for now, in real system use a robust sequence
    const seq = Math.floor(Math.random() * 1000000);
    return `ORD-${Date.now()}-${seq}`;
  }
}
