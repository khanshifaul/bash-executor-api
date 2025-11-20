export enum Role {
  ADMIN = 'ADMIN',
  USER = 'USER',
}

export const mapStringToRoleEnum = (role: string): Role => {
  const roleMap: { [key: string]: Role } = {
    admin: Role.ADMIN,
    user: Role.USER  };

  const enumValue = roleMap[role.toLowerCase()];
  if (!enumValue) {
    throw new Error(`Unsupported role: ${role}`);
  }

  return enumValue;
};
