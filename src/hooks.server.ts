import type { Handle } from '@sveltejs/kit';
import { dev } from '$app/environment';
import * as auth from '$lib/server/auth.js';

export const handle: Handle = async ({ event, resolve }) => {
	const sessionId = event.cookies.get(auth.sessionCookieName);
	if (!sessionId) {
		event.locals.user = null;
		event.locals.session = null;
		return resolve(event);
	}

	const userData = await auth.validateSession(sessionId);
	if (userData.session) {
		event.cookies.set(auth.sessionCookieName, userData.session.id, {
			path: '/',
			sameSite: 'lax',
			httpOnly: true,
			expires: userData.session.expiresAt,
			secure: !dev
		});
	} else {
		event.cookies.delete(auth.sessionCookieName, { path: '/' });
	}

	event.locals.user = userData.user;
	event.locals.session = userData.session;

	return resolve(event);
};
