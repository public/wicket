# Work with a running agent in the console

Watch a boxed ACP agent's session live in the console, prompt it, stop a turn, and decide wicket's
escalations as they come up, from a desktop browser or the console on your phone. The [console
reference](../reference/console.md#sessions) has every rule.

You need:
- a console you can sign in to with a passkey ([install on a host](install-on-a-host.md), or `wicket
  serve` on `http://localhost:8787`; on a phone, [put the console on the
  internet](put-the-console-on-the-internet.md) and add it to the home screen);
- a running ACP agent ([run an ACP agent](run-an-acp-agent.md)), started from the console's **Start
  a run** or with `wicket run`;
- a wicket built with the session view. Release and CI-signed builds have it. A plain `cargo build`
  doesn't: its session page says "This build of wicket has no session view", and `wicket serve` says
  so at start-up. Build one as the [reference](../reference/console.md#sessions) shows.

## 1. Open the session

1. Sign in to the console.
2. In **Runs**, follow the run's **session** link. Only running ACP runs have one.
3. Tap **Open session**. The confirmation at the top of the screen says what your passkey signs:
   *Open run_…'s session as spiffe://…/op/passkey/<name> · agent …*. Check the run, then tap **Sign
   with passkey** and use your passkey.

The header then says **live**. The session plays back from the start of the kept transcript: the
task, the agent's messages and thoughts, its tool calls and plans, and then whatever comes next as
it happens.

If the page says the ticket expired, open it again: a ticket lasts 60 seconds. If it says too many
sessions are open, close the session in another tab or on another device (4 per sign-in, 32 in
all).

## 2. Read what the agent does

- **Messages** are plain text. **thinking** folds the agent's thoughts.
- Each **tool call** is a card with its title, kind and status (pending, running, done, failed).
  **arguments** shows what it was called with, and **result** what came back (diffs show the old
  and new text). "allowed by wicket's policy" or "refused by wicket's policy" is wicket's answer to
  the agent's own permission request for that call. wicket answers those by its policy, once at a
  time; what leaves the box is decided at wicket's gates.
- **Plan** shows the agent's current plan, each entry with its status.
- Prompts from others (the task, another operator, wicket's own notices) show who sent them.

The page follows the stream while you're at the bottom. Scroll up to read, and it stays where you
are.

## 3. Decide an escalation

When the agent asks for something outside its zone, the session shows a card, **wicket is asking
you**, with the method, host, path, risk and the agent's reason.

1. Tap **Approve once (passkey)** or **Deny (passkey)**.
2. The confirmation at the top states the exact decision (for an approval, once for 10 minutes).
   Tap its button and use your passkey.

The card then shows **approved** or **denied**. This is the same signed decision as the cards on
the console's front page, recorded the same way. For a wider grant (an hour, a prefix), decide it on
the front page; the card in the session updates either way.

Answering the prompt any other way (a different ACP client on the same endpoint, for instance)
decides nothing: wicket only records what the client said.

## 4. Prompt the agent, and stop a turn

- Type in the box at the bottom and tap **Send** (on a keyboard, Enter sends and Shift+Enter makes a
  new line). The prompt reaches the agent as its next turn, from your principal. If a turn is
  running, it waits for that turn to end. The header shows **working** until your prompt's turn
  ends.
- **Stop** cancels the agent's running turn, within about a second. The turn ends as `cancelled`,
  and prompts already waiting still run after it. With no turn running, Stop does nothing.

## 5. Close it

Go **‹ Console**, or close the tab. The session also closes when you sign out, when your console
session expires (15 minutes idle, 8 hours in all), or when the run ends. The page then says why and
offers **Reopen**, which asks for your passkey again.

## Check what happened

```sh
wicket audit --tail 500 | grep <run> | grep -E 'session\.|turn_cancel|decision'
```

Every open (with its signed assertion), attach, prompt, cancel and close is there, under your
passkey's name (`passkey:<name>`).
