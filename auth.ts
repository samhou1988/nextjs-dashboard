import { z } from 'zod';
import bcrypt from 'bcrypt';
import NextAuth from 'next-auth';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';

async function getUser(email: string): Promise<User | null> {
  try {
    const user = await sql<User>`
      SELECT * FROM users
      WHERE email = ${email}
    `;
    return user.rows[0] ?? null;
  } catch (error) {
    console.error('Failed to get user:', error);
    throw new Error('Failed to get user');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [Credentials({
    async authorize(credentials) {
      const parsedCredentials = z.object({
        email: z.string().email(),
        password: z.string().min(6),
      }).safeParse(credentials);

      if (parsedCredentials.success) {
        const { email, password } = parsedCredentials.data;
        const user = await getUser(email);
        if (!user) {
          return null;
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) return user;
        return null;
      }
      return null;
    }
  })],
});