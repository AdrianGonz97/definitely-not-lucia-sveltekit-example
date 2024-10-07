<script lang="ts">
	import { enhance } from '$app/forms';
	import type { PageServerData } from './$types';

	export let data: PageServerData;
</script>

<h1>Hi, {data.user.username}!</h1>
<p>Your user ID is {data.user.id}.</p>
<form method="post" action="?/logout" use:enhance>
	<button>Sign out</button>
</form>
