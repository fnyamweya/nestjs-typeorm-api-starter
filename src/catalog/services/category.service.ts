import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Category } from '../entities/category.entity';
import { CategoryTranslation } from '../entities/category-translation.entity';
import { CategoryClosure } from '../entities/category-closure.entity';
import { CreateCategoryDto } from '../dto/create-category.dto';
import { UpdateCategoryDto } from '../dto/update-category.dto';
import { FilterCategoryDto } from '../dto/filter-category.dto';

@Injectable()
export class CategoryService {
  constructor(
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
    @InjectRepository(CategoryTranslation)
    private readonly translationRepository: Repository<CategoryTranslation>,
    @InjectRepository(CategoryClosure)
    private readonly closureRepository: Repository<CategoryClosure>,
  ) {}

  async create(payload: CreateCategoryDto): Promise<Category> {
    const category = this.categoryRepository.create({
      taxonomyId: payload.taxonomyId,
      parentId: payload.parentId,
      key: payload.key,
      slug: payload.slug,
      isActive: payload.isActive ?? true,
      isLeaf: payload.isLeaf ?? false,
      sortOrder: payload.sortOrder ?? 0,
      icon: payload.icon,
      imageUrl: payload.imageUrl,
      metaJson: payload.metaJson ?? {},
    });

    const saved = await this.categoryRepository.save(category);

    await this.createClosureRows(saved.id, payload.parentId);

    if (payload.translations?.length) {
      const translations = payload.translations.map((t) =>
        this.translationRepository.create({ ...t, categoryId: saved.id }),
      );
      await this.translationRepository.save(translations);
    }

    return this.findOne(saved.id);
  }

  async findAll(filters: FilterCategoryDto): Promise<Category[]> {
    const where: Record<string, any> = {
      taxonomyId: filters.taxonomyId,
    };

    if (filters.isActive !== undefined) {
      where.isActive = filters.isActive;
    }

    return this.categoryRepository.find({
      where,
      relations: ['translations'],
      order: { sortOrder: 'ASC', key: 'ASC' },
    });
  }

  async findOne(id: string): Promise<Category> {
    const category = await this.categoryRepository.findOne({
      where: { id },
      relations: ['translations', 'children'],
    });

    if (!category) {
      throw new NotFoundException('Category not found');
    }

    return category;
  }

  async update(id: string, payload: UpdateCategoryDto): Promise<Category> {
    const category = await this.findOne(id);
    const previousParentId = category.parentId;

    if (
      payload.parentId &&
      payload.parentId !== category.parentId &&
      category.children?.length
    ) {
      throw new BadRequestException('Cannot re-parent a category with children');
    }

    Object.assign(category, {
      key: payload.key ?? category.key,
      slug: payload.slug ?? category.slug,
      isActive: payload.isActive ?? category.isActive,
      isLeaf: payload.isLeaf ?? category.isLeaf,
      sortOrder: payload.sortOrder ?? category.sortOrder,
      icon: payload.icon ?? category.icon,
      imageUrl: payload.imageUrl ?? category.imageUrl,
      metaJson: payload.metaJson ?? category.metaJson,
      parentId: payload.parentId ?? category.parentId,
    });

    const saved = await this.categoryRepository.save(category);

    if (payload.parentId !== undefined && payload.parentId !== previousParentId) {
      await this.resetClosureRows(saved.id, payload.parentId);
    }

    if (payload.translations) {
      await this.translationRepository.delete({ categoryId: saved.id });
      const translations = payload.translations.map((t) =>
        this.translationRepository.create({ ...t, categoryId: saved.id }),
      );
      if (translations.length) {
        await this.translationRepository.save(translations);
      }
    }

    return this.findOne(saved.id);
  }

  async remove(id: string): Promise<void> {
    const category = await this.findOne(id);
    await this.categoryRepository.remove(category);
  }

  private async createClosureRows(categoryId: string, parentId?: string) {
    const rows: CategoryClosure[] = [
      this.closureRepository.create({
        ancestorId: categoryId,
        descendantId: categoryId,
        depth: 0,
      }),
    ];

    if (parentId) {
      const ancestorClosures = await this.closureRepository.find({
        where: { descendantId: parentId },
      });

      for (const ancestor of ancestorClosures) {
        rows.push(
          this.closureRepository.create({
            ancestorId: ancestor.ancestorId,
            descendantId: categoryId,
            depth: ancestor.depth + 1,
          }),
        );
      }
    }

    await this.closureRepository.save(rows);
  }

  private async resetClosureRows(categoryId: string, parentId?: string) {
    await this.closureRepository.delete({ descendantId: categoryId });
    await this.createClosureRows(categoryId, parentId);
  }
}
