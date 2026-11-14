export const VALID_ROLES = ['seeker', 'recruiter', 'admin'] as const;

export type Role = (typeof VALID_ROLES)[number];

type UserLike = {
  role?: string | null;
  onboardingComplete?: boolean | null;
} | null | undefined;

export function getRole(user: UserLike): string {
  const role = user?.role;
  if (typeof role === 'string' && (VALID_ROLES as readonly string[]).includes(role)) {
    return role;
  }
  return 'seeker';
}

export function isOnboardingComplete(user: UserLike): boolean {
  return user?.onboardingComplete === true;
}

export function isAdminUser(user: UserLike): boolean {
  return getRole(user) === 'admin';
}
