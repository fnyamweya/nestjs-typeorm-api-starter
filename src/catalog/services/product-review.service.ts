import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource, DeepPartial, Repository } from 'typeorm';
import { Product } from '../entities/product.entity';
import {
  ProductReview,
  ProductReviewStatus,
} from '../entities/product-review.entity';
import { ProductRatingSummary } from '../entities/product-rating-summary.entity';
import { UpsertProductReviewDto } from '../dto/product-review.dto';

@Injectable()
export class ProductReviewService {
  constructor(
    @InjectRepository(ProductReview)
    private readonly reviewRepository: Repository<ProductReview>,
    @InjectRepository(ProductRatingSummary)
    private readonly ratingSummaryRepository: Repository<ProductRatingSummary>,
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectDataSource()
    private readonly dataSource: DataSource,
  ) {}

  async getRatingSummary(productId: string) {
    const summary = await this.ratingSummaryRepository.findOne({
      where: { productId },
    });

    if (!summary) {
      return {
        productId,
        ratingCount: 0,
        avgRating: 0,
        star1Count: 0,
        star2Count: 0,
        star3Count: 0,
        star4Count: 0,
        star5Count: 0,
        updatedAt: null,
      };
    }

    return {
      productId: summary.productId,
      ratingCount: summary.ratingCount,
      avgRating: Number(summary.avgRating),
      star1Count: summary.star1Count,
      star2Count: summary.star2Count,
      star3Count: summary.star3Count,
      star4Count: summary.star4Count,
      star5Count: summary.star5Count,
      updatedAt: summary.updatedAt,
    };
  }

  async listApprovedReviews(
    productId: string,
    page = 1,
    limit = 20,
    sort: 'newest' | 'oldest' | 'highest' | 'lowest' = 'newest',
  ) {
    const qb = this.reviewRepository
      .createQueryBuilder('r')
      .where('r.productId = :productId', { productId })
      .andWhere('r.status = :status', { status: ProductReviewStatus.APPROVED });

    if (sort === 'newest') qb.orderBy('r.createdAt', 'DESC');
    if (sort === 'oldest') qb.orderBy('r.createdAt', 'ASC');
    if (sort === 'highest') qb.orderBy('r.rating', 'DESC').addOrderBy('r.createdAt', 'DESC');
    if (sort === 'lowest') qb.orderBy('r.rating', 'ASC').addOrderBy('r.createdAt', 'DESC');

    const [rows, total] = await qb
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    const data = rows.map((r) => ({
      id: r.id,
      productId: r.productId,
      rating: r.rating,
      title: r.title ?? null,
      body: r.body ?? null,
      mediaUrlsJson: r.mediaUrlsJson ?? [],
      isVerifiedPurchase: r.isVerifiedPurchase,
      createdAt: r.createdAt,
    }));

    return { data, total, page, limit };
  }

  async getMyReview(customerId: string, productId: string) {
    const review = await this.reviewRepository.findOne({
      where: { customerId, productId },
    });

    if (!review) {
      return null;
    }

    return {
      id: review.id,
      productId: review.productId,
      customerId: review.customerId,
      rating: review.rating,
      title: review.title ?? null,
      body: review.body ?? null,
      mediaUrlsJson: review.mediaUrlsJson ?? [],
      isVerifiedPurchase: review.isVerifiedPurchase,
      status: review.status,
      statusReason: review.statusReason ?? null,
      createdAt: review.createdAt,
      updatedAt: review.updatedAt,
    };
  }

  async upsertMyReview(
    customerId: string,
    productId: string,
    payload: UpsertProductReviewDto,
  ) {
    const product = await this.productRepository.findOne({
      where: { id: productId },
      select: ['id'],
    });
    if (!product) {
      throw new NotFoundException('Product not found');
    }

    const existing = await this.reviewRepository.findOne({
      where: { customerId, productId },
    });

    const isVerifiedPurchase = await this.isVerifiedPurchase(
      customerId,
      productId,
    );

    const mediaUrls = payload.mediaUrlsJson ?? [];
    if (mediaUrls.length > 20) {
      throw new BadRequestException('Too many media URLs');
    }

    const nextPayload: DeepPartial<ProductReview> = {
      customerId,
      productId,
      rating: payload.rating,
      title: payload.title?.trim() || undefined,
      body: payload.body?.trim() || undefined,
      mediaUrlsJson: mediaUrls,
      isVerifiedPurchase,
      status: ProductReviewStatus.PENDING,
      statusReason: undefined,
      moderatedByUserId: undefined,
      moderatedAt: undefined,
    };

    if (existing?.id) {
      nextPayload.id = existing.id;
    }

    const wasApproved = existing?.status === ProductReviewStatus.APPROVED;

    const saved = await this.reviewRepository.save(
      this.reviewRepository.create(nextPayload),
    );

    if (wasApproved) {
      await this.recomputeRatingSummary(productId);
    }

    return {
      id: saved.id,
      productId: saved.productId,
      customerId: saved.customerId,
      rating: saved.rating,
      title: saved.title ?? null,
      body: saved.body ?? null,
      mediaUrlsJson: saved.mediaUrlsJson ?? [],
      isVerifiedPurchase: saved.isVerifiedPurchase,
      status: saved.status,
      statusReason: saved.statusReason ?? null,
      createdAt: saved.createdAt,
      updatedAt: saved.updatedAt,
    };
  }

  async deleteMyReview(customerId: string, productId: string) {
    const existing = await this.reviewRepository.findOne({
      where: { customerId, productId },
      select: ['id', 'productId', 'status'],
    });

    if (!existing) {
      return { deleted: false };
    }

    await this.reviewRepository.delete({ id: existing.id });

    if (existing.status === ProductReviewStatus.APPROVED) {
      await this.recomputeRatingSummary(productId);
    }

    return { deleted: true };
  }

  async listPendingReviews(page = 1, limit = 50) {
    const qb = this.reviewRepository
      .createQueryBuilder('r')
      .where('r.status = :status', { status: ProductReviewStatus.PENDING })
      .orderBy('r.createdAt', 'DESC');

    const [rows, total] = await qb
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    const data = rows.map((r) => ({
      id: r.id,
      productId: r.productId,
      customerId: r.customerId,
      rating: r.rating,
      title: r.title ?? null,
      body: r.body ?? null,
      mediaUrlsJson: r.mediaUrlsJson ?? [],
      isVerifiedPurchase: r.isVerifiedPurchase,
      status: r.status,
      statusReason: r.statusReason ?? null,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));

    return { data, total, page, limit };
  }

  async approveReview(reviewId: string, moderatedByUserId: string) {
    const review = await this.reviewRepository.findOne({
      where: { id: reviewId },
    });

    if (!review) {
      throw new NotFoundException('Review not found');
    }

    review.status = ProductReviewStatus.APPROVED;
    review.statusReason = undefined;
    review.moderatedByUserId = moderatedByUserId;
    review.moderatedAt = new Date();

    const saved = await this.reviewRepository.save(review);

    await this.recomputeRatingSummary(saved.productId);

    return saved;
  }

  async rejectReview(
    reviewId: string,
    moderatedByUserId: string,
    statusReason?: string,
  ) {
    const review = await this.reviewRepository.findOne({
      where: { id: reviewId },
    });

    if (!review) {
      throw new NotFoundException('Review not found');
    }

    const wasApproved = review.status === ProductReviewStatus.APPROVED;

    review.status = ProductReviewStatus.REJECTED;
    review.statusReason = statusReason?.trim() || undefined;
    review.moderatedByUserId = moderatedByUserId;
    review.moderatedAt = new Date();

    const saved = await this.reviewRepository.save(review);

    if (wasApproved) {
      await this.recomputeRatingSummary(saved.productId);
    }

    return saved;
  }

  async recomputeRatingSummary(productId: string) {
    const raw = await this.reviewRepository
      .createQueryBuilder('r')
      .select('COUNT(*)', 'ratingCount')
      .addSelect('COALESCE(AVG(r.rating), 0)', 'avgRating')
      .addSelect(
        'SUM(CASE WHEN r.rating = 1 THEN 1 ELSE 0 END)',
        'star1Count',
      )
      .addSelect(
        'SUM(CASE WHEN r.rating = 2 THEN 1 ELSE 0 END)',
        'star2Count',
      )
      .addSelect(
        'SUM(CASE WHEN r.rating = 3 THEN 1 ELSE 0 END)',
        'star3Count',
      )
      .addSelect(
        'SUM(CASE WHEN r.rating = 4 THEN 1 ELSE 0 END)',
        'star4Count',
      )
      .addSelect(
        'SUM(CASE WHEN r.rating = 5 THEN 1 ELSE 0 END)',
        'star5Count',
      )
      .where('r.productId = :productId', { productId })
      .andWhere('r.status = :status', { status: ProductReviewStatus.APPROVED })
      .getRawOne<{
        ratingCount: string;
        avgRating: string;
        star1Count: string;
        star2Count: string;
        star3Count: string;
        star4Count: string;
        star5Count: string;
      }>();

    const record = {
      productId,
      ratingCount: Number(raw?.ratingCount ?? 0),
      avgRating: String(raw?.avgRating ?? 0),
      star1Count: Number(raw?.star1Count ?? 0),
      star2Count: Number(raw?.star2Count ?? 0),
      star3Count: Number(raw?.star3Count ?? 0),
      star4Count: Number(raw?.star4Count ?? 0),
      star5Count: Number(raw?.star5Count ?? 0),
      updatedAt: new Date(),
    };

    await this.ratingSummaryRepository.upsert(record, ['productId']);

    return record;
  }

  private async isVerifiedPurchase(customerId: string, productId: string) {
    const row = await this.dataSource
      .createQueryBuilder()
      .select('1')
      .from('order_item', 'oi')
      .innerJoin('order', 'o', 'o.id = oi.order_id')
      .where('o.customer_id = :customerId', { customerId })
      .andWhere('oi.product_id = :productId', { productId })
      .andWhere("o.status IN ('confirmed', 'completed')")
      .limit(1)
      .getRawOne();

    return !!row;
  }
}
