import {
  Controller,
  Get,
  Query,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { ResponseUtil } from 'src/common/utils/response.util';
import { GooglePlacesService } from 'src/common/google-places/google-places.service';
import { CountryConfigService } from 'src/country/country-config.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Location } from '../entities/location.entity';
import { ILike, Repository } from 'typeorm';

@Controller('locations/google')
@ApiTags('Locations: Google')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth('access-token')
export class GoogleLocationsController {
  constructor(
    private readonly googlePlaces: GooglePlacesService,
    private readonly countryConfig: CountryConfigService,
    @InjectRepository(Location)
    private readonly locationRepo: Repository<Location>,
  ) {}

  @Get('autocomplete')
  @ApiQuery({ name: 'input', required: true, type: String })
  @ApiQuery({
    name: 'countryCode',
    required: false,
    type: String,
    description: 'ISO2 country code, e.g. KE',
  })
  @ApiQuery({
    name: 'language',
    required: false,
    type: String,
    description: 'BCP-47 language code, e.g. en',
  })
  @ApiQuery({
    name: 'sessionToken',
    required: false,
    type: String,
    description: 'Google Places session token',
  })
  @ApiOkResponse({ description: 'Google Places predictions' })
  async autocomplete(
    @Query('input') input: string,
    @Query('countryCode') countryCode?: string,
    @Query('language') language?: string,
    @Query('sessionToken') sessionToken?: string,
  ) {
    const rows = await this.googlePlaces.autocomplete({
      input,
      countryCode: countryCode?.toUpperCase(),
      language,
      sessionToken,
    });
    return ResponseUtil.success(rows, 'Google Places predictions retrieved');
  }

  @Get('details')
  @ApiQuery({ name: 'placeId', required: true, type: String })
  @ApiQuery({ name: 'language', required: false, type: String })
  @ApiQuery({ name: 'sessionToken', required: false, type: String })
  @ApiOkResponse({
    description: 'Google Place details mapped to address fields',
  })
  async details(
    @Query('placeId') placeId: string,
    @Query('language') language?: string,
    @Query('sessionToken') sessionToken?: string,
  ) {
    const details = await this.googlePlaces.placeDetails({
      placeId,
      language,
      sessionToken,
    });
    const mapped = this.googlePlaces.mapPlaceDetailsToAddress(details);
    return ResponseUtil.success(
      {
        place: details,
        mapped,
      },
      'Google Place details retrieved',
    );
  }

  @Get('match')
  @ApiQuery({ name: 'placeId', required: true, type: String })
  @ApiQuery({
    name: 'countryCode',
    required: false,
    type: String,
    description: 'ISO2 country code override, e.g. KE',
  })
  @ApiQuery({ name: 'language', required: false, type: String })
  @ApiQuery({ name: 'sessionToken', required: false, type: String })
  @ApiOkResponse({
    description: 'Best-effort internal Location match preview (no persistence)',
  })
  async match(
    @Query('placeId') placeId: string,
    @Query('countryCode') countryCode?: string,
    @Query('language') language?: string,
    @Query('sessionToken') sessionToken?: string,
  ) {
    const details = await this.googlePlaces.placeDetails({
      placeId,
      language,
      sessionToken,
    });
    const mapped = this.googlePlaces.mapPlaceDetailsToAddress(details);

    const requestedCountry = countryCode?.toUpperCase();
    const googleCountry = mapped.countryCode?.toUpperCase();
    if (
      requestedCountry &&
      googleCountry &&
      requestedCountry !== googleCountry
    ) {
      throw new BadRequestException(
        'countryCode does not match Google Place country',
      );
    }

    const bestCountry = (requestedCountry || googleCountry)?.toUpperCase();
    const candidates =
      await this.countryConfig.extractLocationCandidatesFromGoogle(
        details,
        bestCountry,
      );

    let match: {
      locationId: string;
      matchedType: string;
      matchedName: string;
    } | null = null;
    for (const c of candidates) {
      const found = await this.locationRepo.findOne({
        where: {
          countryCode: bestCountry,
          type: c.type,
          name: ILike(c.name),
        } as any,
      });
      if (found) {
        match = {
          locationId: found.id,
          matchedType: String(c.type),
          matchedName: c.name,
        };
        break;
      }
    }

    return ResponseUtil.success(
      {
        place: details,
        mapped,
        bestCountryCode: bestCountry,
        candidates,
        match,
      },
      'Google Place match preview retrieved',
    );
  }
}
