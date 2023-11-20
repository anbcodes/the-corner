/* This file contains all the code for the application. */

import { hash, verify } from '@node-rs/argon2';
import { randomBytes } from 'crypto';
import { mkdirSync, readdirSync } from 'fs';
import { mkdir, readFile, unlink, writeFile } from 'fs/promises';
import hljs from 'highlight.js';
import http, { IncomingMessage } from 'http';
import MarkdownIt from 'markdown-it';
import { join } from 'path';

// File system "database" code

interface User {
  username: string;
  hash: string;
  bio: string;
  sessions: string[];
}

interface Post {
  title: string;
  content: string;
  id: string;
  author: string;
  date: string;
  replyTo?: string;
  replies: string[];
}

const errors = {
  USER_EXISTS: 'User already exists',
  USER_NOT_FOUND: 'User not found',
  INVALID_USERNAME: 'Invalid username: usename must be between 3 and 20 characters and can only contain letters, numbers, underscores and dashes',
  POST_EXISTS: 'Post already exists',
  INVALID_POST_ID: 'Invalid post id: post id can only contain letters, numbers, underscores and dashes',
  INVALID_POST_TITLE: 'Invalid post title: post title cannot be empty',
  INVALID_POST_CONTENT: 'Invalid post content: post content must be at least 200 characters long',
  INVALID_SESSION: 'Invalid session. Please log in again',
  POST_NOT_FOUND: 'Post not found',
  INVALID_VALUE: 'Invalid value',
  INVALID_PASSWORD: 'Invalid password',
};

type ErrorCode = keyof typeof errors;

class AppError extends Error {
  constructor(public code: ErrorCode, message: string = errors[code]) {
    super(message);
  }
}

// https://stackoverflow.com/a/70887388

type ArbitraryObject = { [key: string]: unknown; };

function isArbitraryObject(potentialObject: unknown): potentialObject is ArbitraryObject {
  return typeof potentialObject === "object" && potentialObject !== null;
}

interface ErrnoException extends Error {
  errno?: number | undefined;
  code?: string | undefined;
  path?: string | undefined;
  syscall?: string | undefined;
}


function isErrnoException(error: unknown): error is ErrnoException {
  return isArbitraryObject(error) &&
    error instanceof Error &&
    (typeof error.errno === "number" || typeof error.errno === "undefined") &&
    (typeof error.code === "string" || typeof error.code === "undefined") &&
    (typeof error.path === "string" || typeof error.path === "undefined") &&
    (typeof error.syscall === "string" || typeof error.syscall === "undefined");
}

const dataFolder = './data';
mkdirSync(dataFolder, { recursive: true });

function checkUsername(username: string) {
  if (username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_\-]+$/.test(username)) {
    throw new AppError('INVALID_USERNAME');
  }
}

async function createUser(username: string, password: string, bio: string): Promise<User> {
  checkUsername(username);

  const hashedPassword = await hash(password);
  const user = { username, bio, hash: hashedPassword, sessions: [] };
  try {
    await writeFile(join(dataFolder, username + '.json'), JSON.stringify(user), { flag: 'wx' });
    return user;
  } catch (e) {
    if (isErrnoException(e) && e.code === 'EEXIST') {
      throw new AppError('USER_EXISTS');
    } else {
      throw e;
    }
  }
}

async function getUser(username: string): Promise<User> {
  try {
    const user = await readFile(join(dataFolder, username + '.json'), { encoding: 'utf-8' });
    return JSON.parse(user);
  } catch (e) {
    if (isErrnoException(e) && e.code === 'ENOENT') {
      throw new AppError('USER_NOT_FOUND');
    } else {
      throw e;
    }
  }
}

async function updateUser(user: User) {
  checkUsername(user.username);
  await writeFile(join(dataFolder, user.username + '.json'), JSON.stringify(user));
}

async function createSession(username: string): Promise<string> {
  const user = await getUser(username);
  const session = randomBytes(32).toString('hex');
  user.sessions.push(session);
  await updateUser(user);
  return `${username}-${session}`;
}

async function getUserFromSession(session: string): Promise<User> {
  const [username, sessionKey] = session.split('-');
  const user = await getUser(username);
  if (!user.sessions.includes(sessionKey)) {
    throw new AppError('INVALID_SESSION');
  }
  return user;
}

function checkPost(post: Post) {
  if (!/^[A-Za-z0-9_\-]+$/.test(post.id)) {
    throw new AppError('INVALID_POST_ID');
  }

  if (post.title.trim().length === 0) {
    throw new AppError('INVALID_POST_TITLE');
  }

  if (post.content.trim().length < 200) {
    throw new AppError('INVALID_POST_CONTENT');
  }
}

async function createPost(post: Post) {
  checkPost(post);

  try {
    await mkdir(join(dataFolder, post.author), { recursive: true });
    await writeFile(join(dataFolder, post.author, post.id) + '.json', JSON.stringify(post), { flag: 'wx' });
    await writeFile(join(dataFolder, '$recent_posts.txt'), `${post.date}/${post.author}/${post.id}\n`, { flag: 'a+' });

    if (post.replyTo) {
      const [author, id] = post.replyTo.split('/');
      const original = await getPost(author, id);
      original.replies.push(`${post.author}/${post.id}`);
      await updatePost(original);
    }
  } catch (e) {
    if (isErrnoException(e) && e.code === 'EEXIST') {
      throw new AppError('POST_EXISTS');
    }
  }
}

async function updatePost(post: Post) {
  checkPost(post);
  await writeFile(join(dataFolder, post.author, post.id) + '.json', JSON.stringify(post));
}

async function deletePost(post: Post) {
  await unlink(join(dataFolder, post.author, post.id));
}

async function getPost(author: string, id: string): Promise<Post> {
  try {
    console.log("Stuff", dataFolder, author, id);
    console.log("Reading", join(dataFolder, author, id) + '.json')
    const post = await readFile(join(dataFolder, author, id) + '.json', { encoding: 'utf-8' });
    return JSON.parse(post);
  } catch (e) {
    if (isErrnoException(e) && e.code === 'ENOENT') {
      throw new AppError('POST_NOT_FOUND');
    } else {
      throw e;
    }
  }
}

async function getPostsForUser(author: string): Promise<Post[]> {
  try {
    const posts = await Promise.all(readdirSync(join(dataFolder, author)).map((id) => getPost(author, id.slice(0, -5))));
    return posts;
  } catch (e) {
    if (isErrnoException(e) && e.code === 'ENOENT') {
      return [];
    } else {
      throw e;
    }
  }
}

async function getMostRecentPosts(last: number): Promise<Post[]> {
  try {
    const recentPosts = await readFile(join(dataFolder, '$recent_posts.txt'), { encoding: 'utf-8' });
    const posts = (await Promise.all(recentPosts.split('\n').slice(-last).map((post) => {
      const [date, author, id] = post.split('/');
      if (!date || !author || !id) return undefined;
      return getPost(author, id);
    }))).filter((post): post is Post => post !== undefined);
    return posts;
  } catch (e) {
    if (isErrnoException(e) && e.code === 'ENOENT') {
      return [];
    } else {
      throw e;
    }
  }
}

// Rendering code

function formatDate(date: string): string {
  // Formats a date like October 1st, 2021
  return new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

function escapeHTML(text?: string): string {
  /* Replaces the following characters with their HTML entity equivalents:
    & -> &amp;
    < -> &lt;
    > -> &gt;
    " -> &#034;
    ' -> &#039;
  */
  if (!text) return '';
  return text.replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&#034;')
    .replace(/'/g, '&#039;');
}

function renderMarkdown(markdown: string): string {
  const md = new MarkdownIt({
    highlight: function (str, lang) {
      if (lang && hljs.getLanguage(lang)) {
        try {
          return hljs.highlight(str, { language: lang }).value;
        } catch (__) { }
      }

      return ''; // use external default escaping
    }
  });
  const html = md.render(markdown);
  return html;
};

function postSummary(content: string) {
  return renderMarkdown(content.slice(0, 200).replace(/[\."'\s]+$/g, '') + '...');
}

function renderPage(head: string, body: string): string {
  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
      body {
        max-width: 700px;
      }
    </style>
    ${head}
  </head>
  <body>
    ${body}
  </body>
  </html>`
}

async function renderHomepage(session?: string): Promise<string> {
  const posts = await getMostRecentPosts(10);
  const user = session ? await getUserFromSession(session) : undefined;
  const e = escapeHTML;
  return renderPage(
    `<title>The Corner</title>`,
    `<h1>The Corner</h1>
    <p>A small corner of the internet for respectful discussion and debate.</p>
    ${user ? `<p>Logged in as ${user.username}</p><a href="/logout">logout</a>` : ''}
    <h2>Recent posts</h2>
    ${posts.map((post) => `
      <h3>${e(post.title)}</h3>
      <p>By <a href="/u/${e(post.author)}">${e(post.author)}</a> on ${formatDate(post.date)} ${post.replyTo ? `replying to <a href="/u/${e(post.replyTo)}">${e(post.replyTo)}</a>` : ''}</p>
      ${postSummary(post.content)}
      <p><a href="/u/${e(post.author)}/${e(post.id)}">Read more</a></p>
    `).join('\n')}
    <p><a href="/new">Create new post</a></p>`
  );
}

async function renderPost(author: string, id: string): Promise<string> {
  const post = await getPost(author, id);
  const e = escapeHTML;
  return renderPage(
    `<title>${e(post.title)} - The Corner</title>`,
    `<h1>${e(post.title)}</h1>
    <p>By <a href="/u/${e(post.author)}">${e(post.author)}</a> on ${formatDate(post.date)} ${post.replyTo ? `replying to <a href="/u/${e(post.replyTo)}">${e(post.replyTo)}</a>` : ''}</p>
    ${renderMarkdown(post.content)}
    <a href="/new?replyTo=${e(post.author)}/${e(post.id)}">Reply</a>
    <h3>Replies</h3>
    <ul>${(post.replies.map((reply) => `
      <li>
        <a href="/u/${e(reply)}">${e(reply)}</a>
      </li>`
    )).join('\n')}
    </ul>

    <a href="/"> Home </a>`
  );
}

async function renderUserpage(user: string, session?: string): Promise<string> {
  const posts = await getPostsForUser(user);
  const currentUser = session ? await getUserFromSession(session) : undefined;
  const e = escapeHTML;
  return renderPage(
    `<title>${e(user)} - The Corner</title>`,
    `<h1>${e(user)}</h1>
    <p>${e((await getUser(user)).bio)}</p>
    ${currentUser?.username === user ? `<a href="/edit-profile">Edit profile</a>` : ''}
    <h2>Posts</h2>
    ${posts.map((post) => `
      <h3>${e(post.title)}</h3>
      <p>By <a href="/u/${e(post.author)}">${e(post.author)}</a> on ${formatDate(post.date)} ${post.replyTo ? `replying to <a href="/u/${e(post.replyTo)}">${e(post.replyTo)}</a>` : ''}</p>
      ${postSummary(post.content)}
      <p><a href="/u/${e(post.author)}/${e(post.id)}">Read more</a></p>
    `).join('\n')}
    <a href="/"> Home </a>`
  );
}

async function renderLoginPage(error?: string): Promise<string> {
  return renderPage(
    `<title>Login - The Corner</title>`,
    `<h1>Login</h1>
    <form method="post" action="/login">
      <label for="username">Username<br>
        <input type="text" name="username" id="username">
      </label><br><br>
      <label for="password">Password<br>
        <input type="password" name="password" id="password">
      </label><br>
      <p>${error ? escapeHTML(error) : ''}</p>
      <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="/register">register</a></p>
    <a href="/">Home</a>`
  );
}

async function renderRegisterPage(error?: string): Promise<string> {
  return renderPage(
    `<title>Register - The Corner</title>`,
    `<h1>Register</h1>
    <form method="post" action="/register">
    <label for="username">Username<br>
        <input type="text" name="username" id="username">
      </label><br><br>
      <label for="password">Password<br>
        <input type="password" name="password" id="password">
      </label><br><br>
      <label for="confirmPassword">Confirm Password<br>
        <input type="password" name="confirmPassword" id="confirmPassword">
      </label><br>
      <p>${error ? escapeHTML(error) : ''}</p>
      <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="/login">login</a></p>
    <a href="/">Home</a>
  `);
}

function renderLogoutPage(): string {
  return renderPage(
    `<title>Logout - The Corner</title>`,
    `<h1>Logout</h1>
      <p>Click below to logout</p>
      <form method="post" action="/logout">
      <button type="submit"> Logout </button>
      </form>
    <a href="/">Home</a>`
  );
}

function renderEditProfilePage(user: User, error?: string): string {
  return renderPage(
    `<title>Edit Profile - The Corner</title>`,
    `<h1>Edit Profile</h1>
    <form method="post" action="/edit-profile">
      <label for="bio">Bio<br>
        <textarea name="bio" id="bio">${escapeHTML(user.bio)}</textarea>
      </label><br>
      <p>${error ? escapeHTML(error) : ''}</p>
      <button type="submit">Save</button>
    </form>
    <p>If you want to change your password or delete your account, you can contact me at me@anb.codes.</p>
    <a href="/">Home</a>`
  );
}

function renderNewPostPage(prev?: { title: string, id: string, content: string }, error?: string, replyTo?: string): string {
  const title = replyTo ? `Replying to ${escapeHTML(replyTo)}` : `New Post`;
  return renderPage(
    `<title>${title} - The Corner</title>`,
    `<h1>${title}</h1>
      <form method="post" action="/new${replyTo ? `?replyTo=${replyTo}` : ''}">
      <input type="hidden" name="replyTo" value="${escapeHTML(replyTo)}">
      <label for="title">Title<br>
        <input type="text" name="title" id="title" value="${escapeHTML(prev?.title)}">
      </label><br><br>
      <label for="id">URL<br>
        <input type="text" name="id" id="id" value="${escapeHTML(prev?.id)}">
      </label><br><br>
      <label for="content">Content<br>
        <textarea name="content" id="content">${escapeHTML(prev?.content)}</textarea>
      </label><br><br>
      <p>I recommend using a website such as <a href="https://stackedit.io/">Stack Edit</a> to write your post in Markdown.</p>
      <p>${error ? escapeHTML(error) : ''}</p>
      <button type="submit">Post</button>
    </form>
    <a href="/">Home</a>`
  );
}

function renderEditPostPage(post: Post, error?: string): string {
  const e = escapeHTML;
  return renderPage(
    `<title>Edit Post: ${e(post.id)} - The Corner</title>`,
    `<h1>Edit Post: ${e(post.id)}</h1>
      <form method="post" action="/edit">
      <input type="hidden" value="${e(post.id)}" name="id">
      <label for="title">Title<br>
        <input type="text" name="title" id="title" value="${e(post.title)}">
      </label><br><br>
      <label for="content">Content<br>
        <textarea name="content" id="content">${e(post.content)}</textarea>
      </label><br>
      <p>${error ? e(error) : ''}</p>
      <button type="submit">Save</button>
    </form>
    <a href="/">Home</a>`
  );
}

// Server code

function getCookies(request: IncomingMessage): { [key: string]: string } {
  const cookieHeader = request.headers.cookie;
  const cookies: { [key: string]: string } = {};

  if (cookieHeader) {
    const cookiePairs = cookieHeader.split(';');
    for (const pair of cookiePairs) {
      const [name, value] = pair.trim().split('=');
      cookies[name] = value;
    }
  }

  return cookies;
}

async function getPostBody(req: IncomingMessage): Promise<URLSearchParams> {
  const body = await new Promise<string>((resolve) => {
    let body = '';
    req.on('data', (chunk) => body += chunk);
    req.on('end', () => resolve(body));
  });
  return new URLSearchParams(body);
}

function required(value: string | null | undefined): string {
  if (!value) {
    throw new AppError('INVALID_VALUE');
  }
  return value;
}

const server = http.createServer(async (req, res) => {
  const cookies = getCookies(req);

  console.log(new Date().toISOString(), req.method, req.url, cookies);

  if (cookies.session) {
    res.setHeader('Cache-Control', 'no-store');
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html');

  try {
    if (req.url === '/') {
      const html = await renderHomepage(cookies.session);
      res.end(html);
    } else if (req.url === '/login') {
      if (req.method === 'GET') {
        const html = await renderLoginPage();
        res.end(html);
      } else if (req.method === 'POST') {
        const body = await getPostBody(req);
        try {
          const username = required(body.get('username'));
          const password = required(body.get('password'));
          const user = await getUser(username);
          if (await verify(user.hash, password)) {
            const session = await createSession(username);
            res.setHeader('Set-Cookie', `session=${session}; HttpOnly; SameSite=Lax`);
            res.statusCode = 302;
            res.setHeader('Location', '/');
            res.end();
          } else {
            throw new AppError('INVALID_PASSWORD');
          }
        } catch (e) {
          if (e instanceof AppError) {
            const html = await renderLoginPage(e.message);
            res.end(html);
          } else {
            throw e;
          }
        }
      }
    } else if (req.url === '/register') {
      if (req.method === 'GET') {
        const html = await renderRegisterPage();
        res.end(html);
      } else if (req.method === 'POST') {
        const body = await getPostBody(req);
        try {
          const username = required(body.get('username'));
          const password = required(body.get('password'));
          const confirmPassword = required(body.get('confirmPassword'));
          if (password === confirmPassword) {
            const user = await createUser(username, password, '');
            const session = await createSession(user.username);
            res.setHeader('Set-Cookie', `session=${session}; HttpOnly; SameSite=Lax`);
            res.statusCode = 302;
            res.setHeader('Location', '/');
            res.end();
          } else {
            const html = await renderRegisterPage('Passwords do not match');
            res.end(html);
          }
        } catch (e) {
          if (e instanceof AppError) {
            const html = await renderRegisterPage(e.message);
            res.end(html);
          } else {
            throw e;
          }
        }
      }
    } else if (req.url === '/logout') {
      if (req.method === 'GET') {
        const html = renderLogoutPage();
        res.end(html);
      } else if (req.method === 'POST') {
        res.setHeader('Set-Cookie', `session=; HttpOnly; SameSite=Lax; Max-Age=0`);
        res.statusCode = 302;
        res.setHeader('Location', '/');
        res.end();
      }
    } else if (req.url === '/edit-profile') {
      if (req.method === 'GET') {
        const user = await getUserFromSession(cookies.session);
        const html = renderEditProfilePage(user);
        res.end(html);
      } else if (req.method === 'POST') {
        const body = await getPostBody(req);
        try {
          const user = await getUserFromSession(cookies.session);
          user.bio = required(body.get('bio'));
          await updateUser(user);
          res.statusCode = 302;
          res.setHeader('Location', `/u/${user.username}`);
          res.end();
        } catch (e) {
          if (e instanceof AppError) {
            const user = await getUserFromSession(cookies.session);
            const html = renderEditProfilePage(user, e.message);
            res.end(html);
          } else {
            throw e;
          }
        }
      }
    } else if (req.url?.startsWith('/new')) {
      if (req.method === 'GET') {
        const replyTo = new URLSearchParams(req.url.split('?')[1]).get('replyTo') ?? undefined;
        if (cookies.session) {
          const html = renderNewPostPage(undefined, undefined, replyTo);
          res.end(html);
        } else {
          res.statusCode = 302;
          res.setHeader('Location', '/login');
          res.end();
        }
      } else if (req.method === 'POST') {
        const body = await getPostBody(req);
        try {
          const title = required(body.get('title'));
          const content = required(body.get('content'));
          const id = required(body.get('id'));
          const replyTo = required(body.get('replyTo'));
          const user = await getUserFromSession(cookies.session);
          const post: Post = {
            title,
            content,
            id,
            author: user.username,
            date: new Date().toISOString(),
            replyTo,
            replies: [],
          }
          await createPost(post);
          res.statusCode = 302;
          res.setHeader('Location', `/u/${user.username}/${id}`);
          res.end();
        } catch (e) {
          if (e instanceof AppError) {
            try {
              const title = required(body.get('title'));
              const content = required(body.get('content'));
              const id = required(body.get('id'));
              const replyTo = required(body.get('replyTo'));
              const html = renderNewPostPage({ title, content, id }, e.message, replyTo);
              res.end(html);
            } catch (_) {
              const html = renderNewPostPage(undefined, e.message, body.get('replyTo') ?? undefined);
              res.end(html);
            }
          } else {
            throw e;
          }
        }
      }
    } else if (req.url?.split('/')[4] === 'edit') {
      const user = await getUserFromSession(cookies.session);
      const [_, _1, author, id] = req.url.split('/');
      if (user.username !== author) {
        res.statusCode = 403;
        res.end('Forbidden');
      }
      const post = await getPost(author, id);
      if (req.method === 'GET') {
        const html = renderEditPostPage(post);
        res.end(html);
      } else if (req.method === 'POST') {
        const body = await getPostBody(req);
        try {
          const title = required(body.get('title'));
          const content = required(body.get('content'));
          const id = required(body.get('id'));
          const newPost: Post = {
            ...post,
            title,
            content,
            id,
          }
          await updatePost(newPost);
        } catch (e) {
          if (e instanceof AppError) {
            const html = renderEditPostPage(post, e.message);
            res.end(html);
          } else {
            throw e;
          }
        }
      }
    } else if (req.url?.split('/')[1] === 'u' && req.url?.split('/').length === 4) {
      const [_, _2, username, id] = req.url.split('/');
      if (req.method === 'GET') {
        const html = await renderPost(username, id);
        res.end(html);
      }
    } else if (req.url?.split('/')[1] === 'u') {
      const [_, _1, username] = req.url.split('/');
      if (req.method === 'GET') {
        const html = await renderUserpage(username, cookies.session);
        res.end(html);
      }
    }
  } catch (e) {
    if (e instanceof AppError) {
      res.statusCode = 400;
      res.end(e.message);
    } else {
      res.statusCode = 500;
      console.error(e);
      res.end('Internal server error');
    }
  }



  // Send not found page if nothing matched
  if (!res.writableEnded) {
    res.statusCode = 404;
    res.end('Not found');
  }
});

const port = 3000;
server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});