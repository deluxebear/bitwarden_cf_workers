import { Hono } from 'hono';
import type { Bindings, Variables } from '../types';

const plans = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const PlanType = {
    Free: 0,
    TeamsAnnually: 18,
    EnterpriseAnnually: 20,
    FamiliesAnnually: 22,
} as const;

const ProductTierType = {
    Free: 0,
    Families: 1,
    Teams: 2,
    Enterprise: 3,
} as const;

function passwordManagerFeatures(options: {
    basePrice: number;
    seatPrice: number;
    baseSeats: number;
    maxSeats: number | null;
    maxCollections: number | null;
    hasAdditionalSeatsOption: boolean;
    hasAdditionalStorageOption: boolean;
    hasPremiumAccessOption: boolean;
    additionalStoragePricePerGb?: number;
    premiumAccessOptionPrice?: number;
}) {
    return {
        StripePlanId: '',
        StripeSeatPlanId: '',
        StripeProviderPortalSeatPlanId: '',
        StripePremiumAccessPlanId: '',
        StripeStoragePlanId: '',
        BasePrice: options.basePrice,
        SeatPrice: options.seatPrice,
        ProviderPortalSeatPrice: options.seatPrice,
        PremiumAccessOptionPrice: options.premiumAccessOptionPrice ?? 0,
        BaseSeats: options.baseSeats,
        MaxAdditionalSeats: options.hasAdditionalSeatsOption ? null : 0,
        MaxSeats: options.maxSeats,
        AdditionalStoragePricePerGb: options.additionalStoragePricePerGb ?? 0,
        HasAdditionalSeatsOption: options.hasAdditionalSeatsOption,
        BaseStorageGb: options.hasAdditionalStorageOption ? 1 : 0,
        MaxCollections: options.maxCollections,
        HasAdditionalStorageOption: options.hasAdditionalStorageOption,
        MaxAdditionalStorage: options.hasAdditionalStorageOption ? null : 0,
        HasPremiumAccessOption: options.hasPremiumAccessOption,
        object: 'passwordManagerPlanFeatures',
    };
}

function secretsManagerFeatures(options: {
    seatPrice: number;
    baseServiceAccount: number;
    additionalPricePerServiceAccount: number;
}) {
    return {
        StripeSeatPlanId: '',
        BaseSeats: 0,
        BasePrice: 0,
        SeatPrice: options.seatPrice,
        HasAdditionalSeatsOption: true,
        MaxAdditionalSeats: null,
        MaxSeats: null,
        StripeServiceAccountPlanId: '',
        AdditionalPricePerServiceAccount: options.additionalPricePerServiceAccount,
        BaseServiceAccount: options.baseServiceAccount,
        MaxServiceAccount: null,
        HasAdditionalServiceAccountOption: true,
        MaxAdditionalServiceAccounts: null,
        MaxProjects: null,
        object: 'secretsManagerPlanFeatures',
    };
}

function plan(options: {
    type: number;
    productTier: number;
    name: string;
    nameLocalizationKey: string;
    descriptionLocalizationKey: string;
    canBeUsedByBusiness: boolean;
    upgradeSortOrder: number;
    displaySortOrder: number;
    passwordManager: ReturnType<typeof passwordManagerFeatures>;
    secretsManager?: ReturnType<typeof secretsManagerFeatures> | null;
}) {
    return {
        Type: options.type,
        ProductTier: options.productTier,
        Name: options.name,
        IsAnnual: true,
        NameLocalizationKey: options.nameLocalizationKey,
        DescriptionLocalizationKey: options.descriptionLocalizationKey,
        CanBeUsedByBusiness: options.canBeUsedByBusiness,
        TrialPeriodDays: options.type === PlanType.EnterpriseAnnually ? 7 : 0,
        HasSelfHost: true,
        HasPolicies: options.productTier >= ProductTierType.Teams,
        HasMyItems: true,
        HasInviteLinks: true,
        HasGroups: options.productTier >= ProductTierType.Teams,
        HasDirectory: options.productTier >= ProductTierType.Teams,
        HasEvents: options.productTier >= ProductTierType.Teams,
        HasTotp: options.productTier >= ProductTierType.Families,
        Has2fa: options.productTier >= ProductTierType.Teams,
        HasApi: options.productTier >= ProductTierType.Teams,
        HasSso: options.productTier >= ProductTierType.Enterprise,
        HasResetPassword: options.productTier >= ProductTierType.Enterprise,
        UsersGetPremium: options.productTier >= ProductTierType.Families,
        UpgradeSortOrder: options.upgradeSortOrder,
        DisplaySortOrder: options.displaySortOrder,
        LegacyYear: 0,
        Disabled: false,
        PasswordManager: options.passwordManager,
        SecretsManager: options.secretsManager ?? null,
        object: 'plan',
    };
}

const AVAILABLE_PLANS = [
    plan({
        type: PlanType.Free,
        productTier: ProductTierType.Free,
        name: 'Free',
        nameLocalizationKey: 'planNameFree',
        descriptionLocalizationKey: 'planDescFreeV2',
        canBeUsedByBusiness: true,
        upgradeSortOrder: 1,
        displaySortOrder: 1,
        passwordManager: passwordManagerFeatures({
            basePrice: 0,
            seatPrice: 0,
            baseSeats: 2,
            maxSeats: 2,
            maxCollections: 2,
            hasAdditionalSeatsOption: false,
            hasAdditionalStorageOption: false,
            hasPremiumAccessOption: false,
        }),
    }),
    plan({
        type: PlanType.FamiliesAnnually,
        productTier: ProductTierType.Families,
        name: 'Families',
        nameLocalizationKey: 'planNameFamilies',
        descriptionLocalizationKey: 'planDescFamiliesV2',
        canBeUsedByBusiness: false,
        upgradeSortOrder: 2,
        displaySortOrder: 2,
        passwordManager: passwordManagerFeatures({
            basePrice: 40,
            seatPrice: 0,
            baseSeats: 6,
            maxSeats: 6,
            maxCollections: null,
            hasAdditionalSeatsOption: false,
            hasAdditionalStorageOption: true,
            hasPremiumAccessOption: false,
            additionalStoragePricePerGb: 4,
        }),
    }),
    plan({
        type: PlanType.TeamsAnnually,
        productTier: ProductTierType.Teams,
        name: 'Teams',
        nameLocalizationKey: 'planNameTeams',
        descriptionLocalizationKey: 'planDescTeamsV2',
        canBeUsedByBusiness: true,
        upgradeSortOrder: 3,
        displaySortOrder: 3,
        passwordManager: passwordManagerFeatures({
            basePrice: 0,
            seatPrice: 48,
            baseSeats: 0,
            maxSeats: null,
            maxCollections: null,
            hasAdditionalSeatsOption: true,
            hasAdditionalStorageOption: true,
            hasPremiumAccessOption: true,
            additionalStoragePricePerGb: 4,
            premiumAccessOptionPrice: 40,
        }),
        secretsManager: secretsManagerFeatures({
            seatPrice: 72,
            baseServiceAccount: 50,
            additionalPricePerServiceAccount: 6,
        }),
    }),
    plan({
        type: PlanType.EnterpriseAnnually,
        productTier: ProductTierType.Enterprise,
        name: 'Enterprise',
        nameLocalizationKey: 'planNameEnterprise',
        descriptionLocalizationKey: 'planDescEnterpriseV2',
        canBeUsedByBusiness: true,
        upgradeSortOrder: 4,
        displaySortOrder: 4,
        passwordManager: passwordManagerFeatures({
            basePrice: 0,
            seatPrice: 72,
            baseSeats: 0,
            maxSeats: null,
            maxCollections: null,
            hasAdditionalSeatsOption: true,
            hasAdditionalStorageOption: true,
            hasPremiumAccessOption: true,
            additionalStoragePricePerGb: 4,
            premiumAccessOptionPrice: 40,
        }),
        secretsManager: secretsManagerFeatures({
            seatPrice: 144,
            baseServiceAccount: 200,
            additionalPricePerServiceAccount: 6,
        }),
    }),
];

plans.get('/', (c) => c.json({
    Data: AVAILABLE_PLANS,
    ContinuationToken: null,
    object: 'list',
}));

plans.get('/premium', (c) => c.json({
    Seat: {
        StripePriceId: 'self-hosted-premium-seat',
        Price: 10,
        Provided: 1,
    },
    Storage: {
        StripePriceId: 'self-hosted-premium-storage',
        Price: 4,
        Provided: 1,
    },
    object: 'premiumPlan',
}));

export default plans;
