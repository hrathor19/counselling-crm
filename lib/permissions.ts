import { prisma } from './prisma';
import { Feature, Role } from '@prisma/client';
import type { User, Lead } from '@prisma/client';

// ─── Permission DB helpers ────────────────────────────────────────────────────

/**
 * SUPER_ADMIN and ROOT_USER are the same access level. They are two enum
 * values rather than one because Manage Permissions stores masking per ROLE
 * (`Permission.role`), not per user — a single admin-tier role would force
 * every Super Admin and every Root User to share one masked/unmasked switch.
 * This is the one place that decides "is this role that level"; every other
 * file that used to compare against `Role.SUPER_ADMIN` alone should call this
 * instead, so the two roles cannot drift apart by one of them forgetting to
 * update when the other changes.
 */
export function isRootLevel(role: Role): boolean {
  return role === Role.SUPER_ADMIN || role === Role.ROOT_USER;
}

// Hardcoded defaults — used as fallback when no DB entry exists
const DEFAULT_PERMISSIONS: Record<Role, Feature[]> = {
  SUPER_ADMIN: Object.values(Feature),
  ROOT_USER: Object.values(Feature),
  // MASK_UNMASK_DATA now means "sees masked data", so REPORTS no longer carries
  // it — they read real values today and still do.
  REPORTS: [Feature.VIEW_REPORTS, Feature.DOWNLOAD_DATA, Feature.APPROVE_LEADS],
  OPERATIONS: [Feature.UPLOAD_LEADS, Feature.MASK_UNMASK_DATA],
  // VIEW_REPORTS included because TLs have always had Analytics/performance
  // access (previously via hardcoded role lists in those routes) — the matrix
  // just didn't reflect it. Toggle it off in Manage Permissions to revoke.
  // Masked by default because a TL's CSV export is already masked today (they
  // hold DOWNLOAD_DATA but not MASK_UNMASK_DATA under the old meaning) — this
  // keeps that true rather than quietly widening what they can see.
  COUNSELLING_TL: [Feature.VIEW_LEADS, Feature.ASSIGN_LEADS, Feature.VIEW_REPORTS, Feature.MASK_UNMASK_DATA],
  COUNSELLING_AGENT: [Feature.VIEW_LEADS, Feature.SUBMIT_FEEDBACK],
};

export async function hasPermission(role: Role, feature: Feature): Promise<boolean> {
  if (isRootLevel(role)) return true;
  const p = await prisma.permission.findUnique({ where: { role_feature: { role, feature } } });
  // If no DB row, fall back to hardcoded defaults so the system works out of the box
  if (p === null) return DEFAULT_PERMISSIONS[role]?.includes(feature) ?? false;
  return p.canAccess;
}

/**
 * Masking is the ONE permission an admin-tier role does not get by default.
 *
 * DEFAULT_PERMISSIONS gives SUPER_ADMIN and ROOT_USER every feature, which is
 * right for all of them except this one — MASK_UNMASK_DATA means "sees masked
 * data", so granting it by default would hide contact details from a role
 * that exists to see everything, the moment the carve-out below was removed.
 *
 * So each admin-tier role starts unmasked and can be masked deliberately
 * (independently of the other — see isRootLevel); every other role keeps
 * whatever DEFAULT_PERMISSIONS says.
 */
function defaultFor(role: Role, feature: Feature): boolean {
  // The one exception to "this role gets everything".
  if (isRootLevel(role) && feature === Feature.MASK_UNMASK_DATA) return false;
  return DEFAULT_PERMISSIONS[role]?.includes(feature) ?? false;
}

function defaultMaskedFor(role: Role): boolean {
  return defaultFor(role, Feature.MASK_UNMASK_DATA);
}

/**
 * Whether this role's lead contact details should be hidden.
 *
 * `MASK_UNMASK_DATA` means "this role sees masked data". The enum keeps its old
 * name because renaming costs an ALTER TYPE and a data migration for no gain;
 * Manage Permissions labels it "Mask Data".
 *
 * Super Admin (and Root User) used to be excluded outright. That carve-out
 * existed because `hasPermission` answers true for an admin-tier role on
 * every feature, so one would have been permanently masked with no way to
 * undo it. The fix is not to exclude the role but to stop its answer coming
 * from that blanket yes — this function reads the stored row directly, keyed
 * by the specific role passed in, and defaultMaskedFor supplies "no" when
 * there is none. Masking is now a deliberate switch, reversible, and set
 * independently for SUPER_ADMIN and ROOT_USER, because the Manage
 * Permissions page is not itself masked.
 */
export async function isMaskedRole(role: Role): Promise<boolean> {
  const p = await prisma.permission.findUnique({
    where: { role_feature: { role, feature: Feature.MASK_UNMASK_DATA } },
  });
  if (p === null) return defaultMaskedFor(role);
  return p.canAccess;
}

export async function getRolePermissions(role: Role): Promise<Record<Feature, boolean>> {
  if (isRootLevel(role)) {
    /**
     * Every feature yes, except masking, which is read like any other role's
     * — and read for THIS role specifically, so SUPER_ADMIN and ROOT_USER
     * each keep their own masked/unmasked state rather than sharing one.
     *
     * This map drives the Manage Permissions grid AND the reports page's mask
     * toggle, so a blanket yes here would show the switch permanently ON while
     * isMaskedRole said otherwise — the screen and the data disagreeing about
     * the same setting.
     */
    const masked = await isMaskedRole(role);
    return Object.values(Feature).reduce(
      (acc, f) => ({ ...acc, [f]: f === Feature.MASK_UNMASK_DATA ? masked : true }),
      {} as Record<Feature, boolean>,
    );
  }
  const perms = await prisma.permission.findMany({ where: { role } });
  return Object.values(Feature).reduce(
    (acc, f) => ({
      ...acc,
      // DB row takes precedence; fall back to hardcoded defaults (not false) when no row exists yet
      [f]: perms.find((p) => p.feature === f)?.canAccess ?? DEFAULT_PERMISSIONS[role]?.includes(f) ?? false,
    }),
    {} as Record<Feature, boolean>
  );
}

export async function getAllPermissions(): Promise<Record<Role, Record<Feature, boolean>>> {
  const perms = await prisma.permission.findMany();
  const result = {} as Record<Role, Record<Feature, boolean>>;
  for (const role of Object.values(Role)) {
    result[role] = Object.values(Feature).reduce(
      (acc, f) => ({
        ...acc,
        // SUPER_ADMIN and ROOT_USER are true for everything EXCEPT masking,
        // which is read from each one's OWN stored row — `perms.find` below
        // is already keyed by `role`, so the two never share a value. This
        // map backs the Manage Permissions grid, so a blanket true here
        // renders the Mask Data switch permanently on: the save succeeds, the
        // grid refetches, and the toggle springs back as though nothing
        // happened.
        [f]: isRootLevel(role) && f !== Feature.MASK_UNMASK_DATA
          ? true
          : (perms.find((p) => p.role === role && p.feature === f)?.canAccess
             ?? defaultFor(role, f)),
      }),
      {} as Record<Feature, boolean>
    );
  }
  return result;
}

// ─── Hierarchy utilities ──────────────────────────────────────────────────────

/**
 * Returns true if actor can view/manage the target user based on role hierarchy.
 * SA can access anyone. TL can access their own agents. Others: only themselves.
 */
export function canAccessUser(actor: User, target: User): boolean {
  if (isRootLevel(actor.role)) return true;
  if (actor.id === target.id) return true;
  if (actor.role === Role.COUNSELLING_TL && target.managedById === actor.id) return true;
  return false;
}

/**
 * Returns true if actor can assign the lead to someone.
 * SA can assign any lead. TL can assign leads that belong to their team.
 */
export function canAssignLead(actor: User, lead: Lead): boolean {
  if (isRootLevel(actor.role)) return true;
  if (actor.role !== Role.COUNSELLING_TL) return false;
  if (lead.status !== 'APPROVED') return false;
  // TL can assign approved leads — team check done at API level with teamId
  return true;
}

/**
 * Returns true if actor is in the management chain above target.
 * SA > TL > Agent hierarchy.
 */
export async function isInHierarchy(actor: User, target: User): Promise<boolean> {
  if (isRootLevel(actor.role)) return true;
  if (actor.id === target.managerId) return true;
  if (actor.id === target.managedById) return true;
  // Walk up one more level: actor manages target's manager
  if (target.managerId) {
    const targetManager = await prisma.user.findUnique({ where: { id: target.managerId } });
    if (targetManager && targetManager.managerId === actor.id) return true;
  }
  return false;
}

// ─── Employee Code generator ──────────────────────────────────────────────────

export async function generateEmployeeCode(): Promise<string> {
  const last = await prisma.user.findFirst({
    where: { employeeCode: { startsWith: 'EMP-' } },
    orderBy: { employeeCode: 'desc' },
    select: { employeeCode: true },
  });
  const next = last
    ? parseInt(last.employeeCode.replace('EMP-', ''), 10) + 1
    : 1;
  return `EMP-${String(next).padStart(3, '0')}`;
}

// ─── Activity Log helper ──────────────────────────────────────────────────────

import type { ActivityAction, Prisma } from '@prisma/client';

/**
 * Actions the activity log deliberately does not record.
 *
 * `CALL_INITIATED` and `CALL_HANGUP` were 65% of every row on production and
 * duplicate `CallLog`, which the dialer's post-call webhook fills in with far
 * more detail — talk time, recording, disposition. Logging them twice bought
 * nothing and made the table two-thirds noise.
 *
 * `FEEDBACK_SUBMITTED` is here for completeness: nothing has ever written it,
 * and feedback is already a first-class `LeadFeedback` row.
 *
 * Filtered centrally rather than by deleting the call sites, so a future caller
 * cannot quietly reintroduce the volume. The enum values stay — historical rows
 * still reference them and must keep rendering.
 */
const UNLOGGED_ACTIONS: ReadonlySet<ActivityAction> = new Set([
  'CALL_INITIATED',
  'CALL_HANGUP',
  'FEEDBACK_SUBMITTED',
] as ActivityAction[]);

export async function logActivity(params: {
  userId: string;
  action: ActivityAction;
  targetId?: string;
  targetType?: string;
  description: string;
  metadata?: Prisma.InputJsonValue;
}): Promise<void> {
  if (UNLOGGED_ACTIONS.has(params.action)) return;
  await prisma.activityLog.create({ data: params });
}
