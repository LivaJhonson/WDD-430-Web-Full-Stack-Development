import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from '@/auth.config'; // adjust path if needed
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';

// Connect to Postgres
const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

// Fetch a user by email from your database
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    return undefined;
  }
}

// NextAuth handler
const handler = NextAuth({
  ...authConfig, // uses your auth.config.ts
  providers: [
    Credentials({
      name: 'Credentials',
      async authorize(credentials) {
        // Validate input using Zod
        const parsed = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsed.success) return null;

        const { email, password } = parsed.data;
        const user = await getUser(email);
        if (!user) return null;

        const passwordsMatch = await bcrypt.compare(password, user.password);
        if (!passwordsMatch) return null;

        // Return user object for session
        return user;
      },
    }),
  ],
  pages: {
    signIn: '/login', // your existing login page
  },
  session: {
    strategy: 'jwt',
  },
});

export { handler as GET, handler as POST };