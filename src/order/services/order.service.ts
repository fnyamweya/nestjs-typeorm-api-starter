import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { In } from 'typeorm';
import { FindManyOptions } from 'typeorm';
import { Order } from '../entities/order.entity';
import { OrderItem } from '../entities/order-item.entity';
import { OrderItemCharge } from '../entities/order-item-charge.entity';
import { OrderLevelCharge } from '../entities/order-level-charge.entity';
import { CreateOrderDto } from '../dto/create-order.dto';
import { PriceService } from '../../catalog/services/price.service';
import { PromotionService } from '../../promotion/services/promotion.service';
import { ProductSku } from '../../catalog/entities/product-sku.entity';
import { Product } from '../../catalog/entities/product.entity';
import { ProductCategory } from '../../catalog/entities/product-category.entity';
import { Category } from '../../catalog/entities/category.entity';
import { CategoryClosure } from '../../catalog/entities/category-closure.entity';
import { PriceList } from '../../catalog/entities/price-list.entity';
import { TaxService } from './tax.service';
import { ShippingMatrixService } from '../../shipping/services/shipping-matrix.service';
import { OrderShippingAddress } from '../entities/order-shipping-address.entity';
import { User } from '../../user/entities/user.entity';
import { CatalogShippingContextService } from '../../shipping/services/catalog-shipping-context.service';
import { Location } from '../../location/entities/location.entity';
import { CurrencyService } from 'src/currency/currency.service';
import { CustomerShippingAddressService } from '../../customer-shipping-address/services/customer-shipping-address.service';

@Injectable()
export class OrderService {
  constructor(
    @InjectRepository(Order)
    private readonly orderRepository: Repository<Order>,
    @InjectRepository(OrderItem)
    private readonly orderItemRepository: Repository<OrderItem>,
    @InjectRepository(OrderItemCharge)
    private readonly orderItemChargeRepository: Repository<OrderItemCharge>,
    @InjectRepository(ProductSku)
    private readonly productSkuRepository: Repository<ProductSku>,
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(ProductCategory)
    private readonly productCategoryRepository: Repository<ProductCategory>,
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
    @InjectRepository(CategoryClosure)
    private readonly categoryClosureRepository: Repository<CategoryClosure>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(PriceList)
    private readonly priceListRepository: Repository<PriceList>,
    @InjectRepository(OrderLevelCharge)
    private readonly orderLevelChargeRepository: Repository<OrderLevelCharge>,
    @InjectRepository(OrderShippingAddress)
    private readonly orderShippingAddressRepository: Repository<OrderShippingAddress>,
    @InjectRepository(Location)
    private readonly locationRepository: Repository<Location>,
    private readonly priceService: PriceService,
    private readonly promotionService: PromotionService,
    private readonly shippingMatrixService: ShippingMatrixService,
    private readonly taxService: TaxService,
    private readonly catalogShippingContextService: CatalogShippingContextService,
    private readonly currencyService: CurrencyService,
    private readonly customerShippingAddressService: CustomerShippingAddressService,
  ) {}

  private allocateProportionally(
    total: number,
    bases: number[],
    decimals = 4,
  ): number[] {
    const n = bases.length;
    if (n === 0) return [];
    if (!Number.isFinite(total) || total <= 0)
      return Array.from({ length: n }, () => 0);

    const safeBases = bases.map((b) => (Number.isFinite(b) && b > 0 ? b : 0));
    const sumBases = safeBases.reduce((a, b) => a + b, 0);
    if (sumBases <= 0) return Array.from({ length: n }, () => 0);

    const factor = 10 ** decimals;
    const rounded: number[] = [];
    let running = 0;

    for (let i = 0; i < n; i++) {
      const raw = (total * safeBases[i]) / sumBases;
      const r = Math.round(raw * factor) / factor;
      rounded.push(r);
      running += r;
    }

    const diff = Math.round((total - running) * factor) / factor;
    if (Math.abs(diff) > 0) {
      // Adjust the largest-base item to absorb rounding diff.
      let idx = 0;
      let best = safeBases[0] ?? 0;
      for (let i = 1; i < n; i++) {
        if ((safeBases[i] ?? 0) > best) {
          best = safeBases[i] ?? 0;
          idx = i;
        }
      }
      rounded[idx] = Math.round((rounded[idx] + diff) * factor) / factor;
    }

    return rounded;
  }

  async create(payload: CreateOrderDto) {
    // Resolve customer identity (orders store email/name snapshot for reporting/receipts)
    const customer = await this.userRepository.findOne({
      where: { id: payload.customerId },
    });
    if (!customer) throw new NotFoundException('Customer not found');
    if (!customer.email)
      throw new BadRequestException('Customer email is missing');

    // Customer shipping address is editable/reusable and is snapshotted onto the order (immutable).
    // If shippingAddress is provided at checkout, we upsert it into the customer's shipping address.
    let customerShippingAddress = await this.customerShippingAddressService
      .getOptionalForUser(payload.customerId)
      .catch(() => null);

    if (payload.shippingAddress) {
      if (!payload.shippingAddress.locationId) {
        throw new BadRequestException('shippingAddress.locationId is required');
      }
      customerShippingAddress =
        await this.customerShippingAddressService.upsertForUser(
          payload.customerId,
          payload.shippingAddress,
        );
    }

    // Backward-compat: if the client only provides shippingLocationId and the customer has no shipping address yet,
    // create a minimal customer shipping address so it can be reused/edited later.
    if (!customerShippingAddress && payload.shippingLocationId) {
      const loc = await this.locationRepository.findOne({
        where: { id: payload.shippingLocationId },
        select: { id: true, countryCode: true } as any,
      });

      if (!loc?.countryCode) {
        throw new BadRequestException('Invalid shippingLocationId');
      }

      customerShippingAddress =
        await this.customerShippingAddressService.upsertForUser(
          payload.customerId,
          {
            countryCode: String(loc.countryCode).toUpperCase(),
            locationId: payload.shippingLocationId,
          } as any,
        );
    }

    const shippingAddress = customerShippingAddress?.address;
    if (shippingAddress && !shippingAddress.locationId) {
      throw new BadRequestException(
        'Customer shipping address must include locationId',
      );
    }

    const resolvedShippingLocationId: string | undefined =
      shippingAddress?.locationId ?? payload.shippingLocationId;

    const shippingSnapshot = shippingAddress
      ? {
          firstName: shippingAddress.firstName ?? customer.firstName,
          lastName: shippingAddress.lastName ?? customer.lastName,
          phone: shippingAddress.phone ?? (customer as any).phone,
          countryCode: shippingAddress.countryCode,
          locationId: shippingAddress.locationId,
          fieldsJson: shippingAddress.fieldsJson ?? {},
        }
      : undefined;

    // Resolve price list if provided
    let priceList: PriceList | null = null;
    if (payload.priceListId) {
      priceList = await this.priceListRepository.findOne({
        where: { id: payload.priceListId },
      });
      if (!priceList) {
        throw new NotFoundException('Price list not found');
      }
    }

    let resolvedPriceList: PriceList | null = priceList;
    if (!resolvedPriceList) {
      const defaultCurrency =
        await this.currencyService.getDefaultCurrencyCode();
      resolvedPriceList =
        await this.priceService.findActivePriceListByCurrency(defaultCurrency);

      if (!resolvedPriceList) {
        resolvedPriceList = await this.priceListRepository.findOne({
          where: { status: 'active' as any },
          order: { priority: 'DESC' as any, createdAt: 'DESC' as any },
        });
      }

      if (!resolvedPriceList) {
        throw new NotFoundException('No active price list available');
      }
    }

    const order = this.orderRepository.create({
      orderNumber: await this.generateOrderNumber(),
      customerId: payload.customerId,
      customerEmail: customer.email,
      customerName:
        [customer.firstName, customer.lastName].filter(Boolean).join(' ') ||
        undefined,
      priceListId: resolvedPriceList.id,
      currencyCode: await this.currencyService.assertExists(
        resolvedPriceList.currency,
      ),
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

    const pricingContext = resolvedShippingLocationId
      ? {
          countryCode: (
            await this.locationRepository.findOne({
              where: { id: resolvedShippingLocationId },
              select: { id: true, countryCode: true },
            })
          )?.countryCode,
        }
      : undefined;

    // Persist an order-level shipping snapshot (so the order is immutable even if the customer address changes).
    if (shippingSnapshot || resolvedShippingLocationId) {
      await this.orderShippingAddressRepository.save(
        this.orderShippingAddressRepository.create({
          orderId: savedOrder.id,
          firstName: shippingSnapshot?.firstName,
          lastName: shippingSnapshot?.lastName,
          phone: shippingSnapshot?.phone,
          countryCode: shippingSnapshot?.countryCode,
          locationId:
            shippingSnapshot?.locationId ?? resolvedShippingLocationId,
          fieldsJson: shippingSnapshot?.fieldsJson ?? {},
        }),
      );
    }

    let itemsSubtotal = 0;
    let totalItemCount = 0;
    const productIds = new Set<string>();

    for (const item of payload.orderItems) {
      const sku = await this.productSkuRepository.findOne({
        where: { id: item.productSkuId },
      });
      if (!sku) {
        throw new NotFoundException('Product SKU not found');
      }

      productIds.add(sku.productId);

      const resolved = await this.priceService.resolveSkuPrice({
        productSkuId: item.productSkuId,
        productId: sku.productId,
        priceListId: priceList?.id ?? savedOrder.priceListId,
        currencyCode: savedOrder.currencyCode,
        quantity: item.quantity,
        context: pricingContext,
      });

      const unitPrice = parseFloat(resolved.unitPrice);
      const baseSubtotal = unitPrice * item.quantity;

      itemsSubtotal += baseSubtotal;
      totalItemCount += item.quantity;

      const orderItem = this.orderItemRepository.create({
        orderId: savedOrder.id,
        productId: sku.productId,
        productSkuId: sku.id,
        sku: sku.sku,
        productName: sku.title,
        skuTitle: sku.title,
        skuOptionsJson: {},
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
        requiresShipping: sku.requiresShipping,
        fulfillmentStatus: 'unfulfilled',
        pricingSnapshotJson: { resolved },
        // Persist the SKU weight so later total weight calculation can read it from the order item
        metaJson: { weight: (sku as any).weight ?? (sku.attributes as any)?.weight },
      });

      await this.orderItemRepository.save(orderItem);
    }

    savedOrder.itemsSubtotal = itemsSubtotal.toFixed(4);
    savedOrder.itemCount = totalItemCount;

    // Shipping calculation using the ShippingMatrixService (select best candidate)
    // compute total weight from items (attempt to use SKU weight if set)
    let totalWeight = 0;
    const items = await this.orderItemRepository.find({
      where: { orderId: savedOrder.id },
    });
    for (const it of items) {
      const weight = Number(
        (it as any).weight || (it as any).metaJson?.weight || 0,
      );
      totalWeight += (it.quantity || 0) * (weight || 0);
    }

    const catalogShipping =
      await this.catalogShippingContextService.resolveCatalogShippingContext(
        Array.from(productIds),
      );

    const quotes = resolvedShippingLocationId
      ? await this.shippingMatrixService.getQuotes({
          locationId: resolvedShippingLocationId,
          subtotal: itemsSubtotal,
          totalWeight,
          itemCount: totalItemCount,
          currencyCode: savedOrder.currencyCode,
          channelCode: savedOrder.salesChannelCode,
          allowedMethodCodes: catalogShipping.allowedMethodCodes,
          excludedMethodCodes: catalogShipping.excludedMethodCodes,
          ratePriorityBoost: catalogShipping.ratePriorityBoost,
          productIds: catalogShipping.productIds,
          categoryIds: catalogShipping.categoryIds,
          taxonomyIds: catalogShipping.taxonomyIds,
        })
      : [];

    let best = quotes[0];
    if (payload.shippingMethodCode) {
      const code = String(payload.shippingMethodCode).trim();
      const candidates = quotes.filter((q) => q.method?.code === code);
      if (!candidates.length) {
        throw new BadRequestException(
          'Selected shipping method is not available for this destination',
        );
      }

      candidates.sort(
        (a, b) =>
          (b.effectivePriority ?? 0) - (a.effectivePriority ?? 0) ||
          (a.amount ?? 0) - (b.amount ?? 0),
      );
      best = candidates[0];
    }
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
        metaJson: best
          ? {
              methodId: best.method.id,
              rateId: best.rate.id,
              meta: best.rate.metaJson,
            }
          : {},
      });
      await this.orderLevelChargeRepository.save(shippingCharge);
    }

    savedOrder.shippingSubtotal = shippingFee.toFixed(4);

    // Build promotion item targeting context (products/categories/taxonomies/tags)
    const promoProductIds = Array.from(
      new Set(
        items.map((it) => it.productId).filter((x): x is string => Boolean(x)),
      ),
    );

    const productTagsById = new Map<string, string[]>();
    if (promoProductIds.length) {
      const products = await this.productRepository.find({
        where: { id: In(promoProductIds) },
        select: { id: true, metaJson: true } as any,
      });
      for (const p of products) {
        const meta: any = (p as any).metaJson ?? {};
        const tags = Array.isArray(meta.tags)
          ? meta.tags
              .map(String)
              .map((t: string) => t.trim())
              .filter(Boolean)
          : [];
        productTagsById.set(p.id, tags);
      }
    }

    const categoryIdsByProductId = new Map<string, Set<string>>();
    const taxonomyIdsByProductId = new Map<string, Set<string>>();

    if (promoProductIds.length) {
      const pcs = await this.productCategoryRepository.find({
        where: { productId: In(promoProductIds) },
      });

      const directCategoryIds = Array.from(
        new Set(pcs.map((pc) => pc.categoryId)),
      );

      // Include ancestor categories so promotions targeting a parent category match items in descendant categories.
      const ancestorIdsByDescendantId = new Map<string, Set<string>>();
      if (directCategoryIds.length) {
        const closureRows = await this.categoryClosureRepository.find({
          where: { descendantId: In(directCategoryIds) },
          select: ['descendantId', 'ancestorId', 'depth'],
        });

        for (const row of closureRows) {
          if (!ancestorIdsByDescendantId.has(row.descendantId)) {
            ancestorIdsByDescendantId.set(row.descendantId, new Set());
          }
          ancestorIdsByDescendantId.get(row.descendantId)!.add(row.ancestorId);
        }
      }

      const expandedCategoryIds = new Set<string>(directCategoryIds);
      for (const [_, ancestors] of ancestorIdsByDescendantId) {
        for (const a of ancestors) expandedCategoryIds.add(a);
      }

      const categories = expandedCategoryIds.size
        ? await this.categoryRepository.find({
            where: { id: In(Array.from(expandedCategoryIds)) },
          })
        : [];
      const taxonomyByCategoryId = new Map(
        categories.map((c) => [c.id, c.taxonomyId] as const),
      );

      for (const pc of pcs) {
        const pid = pc.productId;
        if (!categoryIdsByProductId.has(pid))
          categoryIdsByProductId.set(pid, new Set());

        const catIds = new Set<string>();
        catIds.add(pc.categoryId);
        const ancestors = ancestorIdsByDescendantId.get(pc.categoryId);
        if (ancestors) {
          for (const a of ancestors) catIds.add(a);
        }

        for (const categoryId of catIds) {
          categoryIdsByProductId.get(pid)!.add(categoryId);
          const taxonomyId = taxonomyByCategoryId.get(categoryId);
          if (taxonomyId) {
            if (!taxonomyIdsByProductId.has(pid))
              taxonomyIdsByProductId.set(pid, new Set());
            taxonomyIdsByProductId.get(pid)!.add(taxonomyId);
          }
        }
      }
    }

    const promoItems = items.map((it) => {
      const pid = it.productId;
      return {
        productId: pid,
        productSkuId: it.productSkuId,
        quantity: it.quantity,
        categoryIds: pid
          ? Array.from(categoryIdsByProductId.get(pid) ?? [])
          : [],
        taxonomyIds: pid
          ? Array.from(taxonomyIdsByProductId.get(pid) ?? [])
          : [],
        tags: pid ? Array.from(new Set(productTagsById.get(pid) ?? [])) : [],
      };
    });

    // Evaluate promotions and apply discounts (dynamic promotion engine)
    const promoResult = await this.promotionService.evaluatePromotions({
      subtotal: savedOrder.itemsSubtotal,
      currencyCode: savedOrder.currencyCode,
      shippingFee: shippingFee.toFixed(4),
      customerId: payload.customerId,
      items: promoItems,
    });

    const totalDiscount = Number(promoResult.totalDiscount || '0');
    const shippingDiscount = Number(
      (promoResult as any).shippingDiscount || '0',
    );

    // Allocate order-level promotion discount to items and persist per-item charges.
    if (totalDiscount > 0 && items.length) {
      const itemBases = items.map((it) => Number(it.baseSubtotal || '0'));
      const allocations = this.allocateProportionally(
        totalDiscount,
        itemBases,
        4,
      );

      const discountCharges: OrderItemCharge[] = [];
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        const allocated = allocations[i] ?? 0;
        if (!allocated) continue;

        it.discountTotal = allocated.toFixed(4);

        discountCharges.push(
          this.orderItemChargeRepository.create({
            orderItemId: it.id,
            chargeKind: 'discount',
            code:
              promoResult.applied?.map((a) => a.code).join(',') || undefined,
            displayName: 'Promotion Discount',
            calculationType: 'fixed',
            baseAmount: it.baseSubtotal,
            quantityBasis: it.quantity,
            amount: (-allocated).toFixed(4),
            isIncludedInPrice: false,
            sourceType: 'promotion',
            sourceReference:
              promoResult.applied?.map((a) => a.promotionId).join(',') ||
              undefined,
            metaJson: {
              applied: promoResult.applied ?? [],
              allocationBasis: 'base_subtotal',
            },
          }),
        );
      }

      if (discountCharges.length) {
        await this.orderItemChargeRepository.save(discountCharges);
      }
    }

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
        sourceReference: promoResult.applied
          .map((a) => a.promotionId)
          .join(','),
        metaJson: { applied: promoResult.applied },
      });
      await this.orderLevelChargeRepository.save(charge);
    }

    if (shippingDiscount > 0) {
      const shippingDiscCharge = this.orderLevelChargeRepository.create({
        orderId: savedOrder.id,
        chargeKind: 'discount',
        code: promoResult.applied.map((a) => a.code).join(','),
        displayName: 'Shipping Discount',
        calculationType: 'fixed',
        baseAmount: savedOrder.shippingSubtotal,
        amount: (-shippingDiscount).toFixed(4),
        isIncludedInPrice: false,
        appliesToShipping: true,
        sourceType: 'promotion',
        sourceReference: promoResult.applied
          .map((a) => a.promotionId)
          .join(','),
        metaJson: { applied: promoResult.applied },
      });
      await this.orderLevelChargeRepository.save(shippingDiscCharge);
    }

    savedOrder.discountTotal = totalDiscount.toFixed(4);
    savedOrder.shippingDiscount = shippingDiscount.toFixed(4);

    // Tax calculation using TaxService for configurable tax rate
    const shippingNet = Math.max(0, shippingFee - shippingDiscount);
    const taxable = itemsSubtotal - totalDiscount + shippingNet;
    const taxResult = await this.taxService.calculateTax({
      taxableAmount: taxable,
      currencyCode: savedOrder.currencyCode,
    });

    const taxAmount = Number(taxResult.amount || 0);

    // Allocate tax between items and shipping (so order.taxTotal represents item tax, order.shippingTax represents shipping tax).
    const itemTaxableBases = items.map((it) =>
      Math.max(
        0,
        Number(it.baseSubtotal || '0') - Number(it.discountTotal || '0'),
      ),
    );
    const basesWithShipping = [...itemTaxableBases, shippingNet];
    const taxAllocations = this.allocateProportionally(
      taxAmount,
      basesWithShipping,
      4,
    );

    const taxCharges: OrderItemCharge[] = [];
    let itemTaxSum = 0;
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const allocated = taxAllocations[i] ?? 0;
      it.taxTotal = allocated.toFixed(4);
      itemTaxSum += allocated;

      if (allocated > 0) {
        taxCharges.push(
          this.orderItemChargeRepository.create({
            orderItemId: it.id,
            chargeKind: 'tax',
            displayName: 'Tax',
            calculationType: taxResult.rate ? 'percentage' : 'fixed',
            rate: (taxResult.rate || 0).toFixed(6) as any,
            baseAmount: Math.max(0, itemTaxableBases[i] ?? 0).toFixed(4),
            quantityBasis: it.quantity,
            amount: allocated.toFixed(4),
            isIncludedInPrice: false,
            sourceType: 'tax',
            metaJson: taxResult.meta || {},
          }),
        );
      }
    }

    const shippingTax = taxAllocations[items.length] ?? 0;

    if (taxCharges.length) {
      await this.orderItemChargeRepository.save(taxCharges);
    }

    // Update per-item totals now that discounts/tax are known.
    for (const it of items) {
      const base = Number(it.baseSubtotal || '0');
      const discount = Number(it.discountTotal || '0');
      const fee = Number(it.feeTotal || '0');
      const tax = Number(it.taxTotal || '0');
      it.total = (base - discount + fee + tax).toFixed(4);
    }
    await this.orderItemRepository.save(items);

    // Persist order-level tax charges (split items vs shipping).
    if (itemTaxSum > 0) {
      const taxChargeItems = this.orderLevelChargeRepository.create({
        orderId: savedOrder.id,
        chargeKind: 'tax',
        displayName: 'Tax',
        calculationType: taxResult.rate ? 'percentage' : 'fixed',
        rate: (taxResult.rate || 0).toFixed(6) as any,
        baseAmount: (itemsSubtotal - totalDiscount).toFixed(4),
        amount: itemTaxSum.toFixed(4),
        isIncludedInPrice: false,
        appliesToShipping: false,
        sourceType: 'tax',
        metaJson: taxResult.meta || {},
      });
      await this.orderLevelChargeRepository.save(taxChargeItems);
    }

    if (shippingTax > 0) {
      const taxChargeShipping = this.orderLevelChargeRepository.create({
        orderId: savedOrder.id,
        chargeKind: 'tax',
        displayName: 'Shipping Tax',
        calculationType: taxResult.rate ? 'percentage' : 'fixed',
        rate: (taxResult.rate || 0).toFixed(6) as any,
        baseAmount: shippingNet.toFixed(4),
        amount: shippingTax.toFixed(4),
        isIncludedInPrice: false,
        appliesToShipping: true,
        sourceType: 'tax',
        metaJson: taxResult.meta || {},
      });
      await this.orderLevelChargeRepository.save(taxChargeShipping);
    }

    savedOrder.taxTotal = itemTaxSum.toFixed(4);
    savedOrder.shippingTax = shippingTax.toFixed(4);
    savedOrder.shippingTotal = (shippingNet + shippingTax).toFixed(4);

    // Grand total: itemsSubtotal - discounts + shipping + tax
    savedOrder.grandTotal = (
      itemsSubtotal -
      totalDiscount +
      shippingNet +
      taxAmount
    ).toFixed(4);

    const updated = await this.orderRepository.save(savedOrder);

    // Return hydrated order so clients can see item charges + order level charges in one response.
    const hydrated = await this.orderRepository.findOne({
      where: { id: updated.id },
      relations: ['items', 'items.itemCharges', 'orderLevelCharges'],
    } as any);

    return hydrated ?? updated;
  }

  async findAndCount(options: FindManyOptions<Order>) {
    return this.orderRepository.findAndCount(options);
  }

  async findOneHydrated(id: string): Promise<Order> {
    const order = await this.orderRepository.findOne({
      where: { id },
      relations: ['items', 'items.itemCharges', 'orderLevelCharges'],
    } as any);
    if (!order) throw new NotFoundException('Order not found');
    return order;
  }

  private async generateOrderNumber() {
    // Simple generator for now, in real system use a robust sequence
    const seq = Math.floor(Math.random() * 1000000);
    return `ORD-${Date.now()}-${seq}`;
  }
}
