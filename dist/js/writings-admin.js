/* Saint Gordon Collective — Stripped-Down WordPress-Style Writings Admin */
(function () {
  "use strict";

  const MD = window.SaintWritingsMarkdown;
  const CRYPTO = window.SaintCrypto;
  if (!MD) return;

  const API_URL = "/api/writings";
  const DRAFT_STORAGE_KEY = "sg_writings_autosave_v1";
  const TOKEN_STORAGE_KEY = "sg_writings_gh_token";

  const state = {
    authenticated: false,
    cloudConfigured: false,
    posts: [],
    media: [],
    postFilter: "all",
    postSearch: "",
    editingOriginalSlug: "",
    slugManuallyEdited: false,
    viewMode: "split",
    busy: false,
    lockoutTimer: null,
    lockoutUntilMs: 0,
  };

  const $ = function (id) { return document.getElementById(id); };

  const dom = {
    lockScreen: $("admin-lock-screen"),
    loginForm: $("admin-login-form"),
    passwordInput: $("admin-password-input"),
    loginError: $("admin-login-error"),
    loginBtn: $("btn-admin-login"),
    dashboard: $("admin-dashboard"),
    cloudStatusBtn: $("btn-cloud-status"),
    btnNewPost: $("btn-new-post"),
    btnLogout: $("btn-admin-logout"),
    tabPostsCount: $("tab-posts-count"),
    tabMediaCount: $("tab-media-count"),
    panelPosts: $("panel-posts"),
    panelEditor: $("panel-editor"),
    panelMedia: $("panel-media"),
    panelSetup: $("panel-setup"),
    postsList: $("admin-posts-list"),
    postsSearch: $("admin-posts-search"),
    btnRefreshPosts: $("btn-refresh-posts"),
    edTitle: $("ed-title"),
    edSlug: $("ed-slug"),
    edDate: $("ed-date"),
    edTags: $("ed-tags"),
    edStatus: $("ed-status"),
    edPinned: $("ed-pinned"),
    edSummary: $("ed-summary"),
    edCover: $("ed-cover"),
    edCoverPreview: $("ed-cover-preview"),
    edCoverFile: $("ed-cover-file"),
    edCoverXerox: $("ed-cover-xerox"),
    btnUploadCover: $("btn-upload-cover"),
    btnClearCover: $("btn-clear-cover"),
    edBody: $("ed-body"),
    edPreview: $("ed-preview"),
    editorWorkspace: $("editor-workspace"),
    edStats: $("ed-stats"),
    edAutosaveStatus: $("ed-autosave-status"),
    btnInsertImage: $("btn-insert-image"),
    btnInsertVideo: $("btn-insert-video"),
    edInlineImageFile: $("ed-inline-image-file"),
    btnDownloadMd: $("btn-download-md"),
    btnSaveDraft: $("btn-save-draft"),
    btnPublishPost: $("btn-publish-post"),
    mediaDropzone: $("media-dropzone"),
    mediaUploadInput: $("media-upload-input"),
    btnMediaPick: $("btn-media-pick"),
    mediaOptCompress: $("media-opt-compress"),
    mediaOptXerox: $("media-opt-xerox"),
    mediaGrid: $("media-grid"),
    setupStatusCopy: $("setup-status-copy"),
    setupBrowserToken: $("setup-browser-token"),
    btnSaveBrowserToken: $("btn-save-browser-token"),
    btnClearBrowserToken: $("btn-clear-browser-token"),
    embedModal: $("embed-modal"),
    embedUrlInput: $("embed-url-input"),
    embedCaptionInput: $("embed-caption-input"),
    embedVideoFile: $("embed-video-file"),
    btnUploadClip: $("btn-upload-clip"),
    btnEmbedCancel: $("btn-embed-cancel"),
    btnEmbedInsert: $("btn-embed-insert"),
    toast: $("admin-toast"),
  };

  function showToast(msg, durationMs) {
    if (!dom.toast) return;
    dom.toast.textContent = msg;
    dom.toast.classList.remove("hidden");
    clearTimeout(showToast._t);
    showToast._t = setTimeout(function () {
      dom.toast.classList.add("hidden");
    }, durationMs || 2800);
  }

  function getBrowserToken() {
    try {
      return (window.localStorage.getItem(TOKEN_STORAGE_KEY) || "").trim();
    } catch (_) {
      return "";
    }
  }

  function hasWriteCapability() {
    return state.cloudConfigured || Boolean(getBrowserToken());
  }

  function authHeaders(extra) {
    const h = Object.assign({ "Content-Type": "application/json" }, extra || {});
    const bt = getBrowserToken();
    if (bt && !state.cloudConfigured) {
      h["X-GitHub-Token"] = bt;
    }
    return h;
  }

  async function apiGet(query) {
    const resp = await fetch(API_URL + "?" + query, {
      credentials: "same-origin",
      headers: getBrowserToken() && !state.cloudConfigured ? { "X-GitHub-Token": getBrowserToken() } : {},
    });
    const data = await resp.json().catch(function () { return {}; });
    if (!resp.ok) {
      const err = new Error(data.error || "Request failed (" + resp.status + ")");
      err.code = data.code || "";
      err.status = resp.status;
      err.retryAfter = Number(data.retryAfter || 0);
      throw err;
    }
    return data;
  }

  async function apiPost(payload) {
    const resp = await fetch(API_URL, {
      method: "POST",
      credentials: "same-origin",
      headers: authHeaders(),
      body: JSON.stringify(payload),
    });
    const data = await resp.json().catch(function () { return {}; });
    if (!resp.ok) {
      const err = new Error(data.error || "Request failed (" + resp.status + ")");
      err.code = data.code || "";
      err.status = resp.status;
      err.retryAfter = Number(data.retryAfter || 0);
      throw err;
    }
    return data;
  }

  function todayIso() {
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, "0");
    const d = String(now.getDate()).padStart(2, "0");
    return y + "-" + m + "-" + d;
  }

  /* ========================================================================
     TABS & CLOUD STATUS
     ======================================================================== */
  function switchTab(tabName) {
    document.querySelectorAll(".admin-tab").forEach(function (btn) {
      const active = btn.dataset.tab === tabName;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", String(active));
    });
    dom.panelPosts.classList.toggle("hidden", tabName !== "posts");
    dom.panelEditor.classList.toggle("hidden", tabName !== "editor");
    dom.panelMedia.classList.toggle("hidden", tabName !== "media");
    dom.panelSetup.classList.toggle("hidden", tabName !== "setup");
  }

  function updateCloudStatusUI() {
    const bt = getBrowserToken();
    if (state.cloudConfigured) {
      dom.cloudStatusBtn.textContent = "● CLOUD CONNECTED";
      dom.cloudStatusBtn.classList.add("connected");
      dom.setupStatusCopy.innerHTML =
        "<strong>Connected via Vercel <code>GITHUB_TOKEN</code>.</strong> You can publish, edit, delete posts, and upload media from any device using only your admin password.";
    } else if (bt) {
      dom.cloudStatusBtn.textContent = "● BROWSER TOKEN ACTIVE";
      dom.cloudStatusBtn.classList.add("connected");
      dom.setupStatusCopy.innerHTML =
        "<strong>Connected using your browser fallback token.</strong> Publishing works right now on this device. Add <code>GITHUB_TOKEN</code> in Vercel Environment Variables whenever you want password-only publishing across all devices.";
    } else {
      dom.cloudStatusBtn.textContent = "○ CONNECT GITHUB TO PUBLISH";
      dom.cloudStatusBtn.classList.remove("connected");
      dom.setupStatusCopy.innerHTML =
        "Your admin password is verified, but <code>GITHUB_TOKEN</code> is not set in Vercel yet. Follow the 3 steps below (or paste a scoped fallback token) so clicking Publish commits straight to GitHub.";
    }
    if (dom.setupBrowserToken) dom.setupBrowserToken.value = bt;
  }

  /* ========================================================================
     AUTHENTICATION (ZERO-PLAINTEXT SHA3-512 CHALLENGE-RESPONSE + LOCKOUT)
     ======================================================================== */
  function formatCountdown(sec) {
    const s = Math.max(0, Math.ceil(sec));
    const m = Math.floor(s / 60);
    const r = s % 60;
    return m > 0 ? String(m).padStart(2, "0") + ":" + String(r).padStart(2, "0") : r + "s";
  }

  function clearLockoutCountdown() {
    if (state.lockoutTimer) {
      clearInterval(state.lockoutTimer);
      state.lockoutTimer = null;
    }
    state.lockoutUntilMs = 0;
    dom.passwordInput.disabled = false;
    dom.loginBtn.disabled = false;
    dom.loginBtn.textContent = "Unlock Portal ↗";
  }

  function startLockoutCountdown(seconds, prefixMsg) {
    const secs = Math.max(1, Math.ceil(Number(seconds) || 0));
    clearLockoutCountdown();
    state.lockoutUntilMs = Date.now() + secs * 1000;
    dom.passwordInput.disabled = true;
    dom.loginBtn.disabled = true;

    const tick = function () {
      const rem = Math.ceil((state.lockoutUntilMs - Date.now()) / 1000);
      if (rem <= 0) {
        clearLockoutCountdown();
        dom.loginError.classList.add("hidden");
        dom.passwordInput.focus();
        return;
      }
      const label = formatCountdown(rem);
      dom.loginBtn.textContent = "Locked (" + label + ")";
      dom.loginError.textContent = (prefixMsg || "Too many failed attempts.") + " Try again in " + label + ".";
      dom.loginError.classList.remove("hidden");
    };

    tick();
    state.lockoutTimer = setInterval(tick, 250);
  }

  function showNotFoundScreen() {
    clearLockoutCountdown();
    document.title = "404 — Page Not Found | Saint Gordon Collective";
    dom.dashboard.classList.add("hidden");
    dom.lockScreen.classList.remove("hidden");
    dom.lockScreen.innerHTML =
      '<div class="admin-lock-head micro"><span>HTTP 404 // NOT FOUND</span><span>SAINT GORDON</span></div>' +
      '<h1 class="admin-lock-title">Page Not Found.</h1>' +
      '<p class="admin-lock-sub">The page you are looking for does not exist or has been moved.</p>' +
      '<a class="admin-lock-btn" style="display:block;text-align:center;text-decoration:none;" href="/">← Return Home</a>';
  }

  async function checkSession() {
    try {
      const data = await apiGet("action=session");
      state.authenticated = Boolean(data.authenticated);
      state.cloudConfigured = Boolean(data.cloudConfigured);
      if (!state.authenticated && Number(data.retryAfter || 0) > 0) {
        startLockoutCountdown(data.retryAfter, "Please wait before trying again.");
      }
    } catch (err) {
      if (err && (err.status === 404 || err.status === 403 || err.code === "GEO_BLOCKED")) {
        showNotFoundScreen();
        return;
      }
      state.authenticated = false;
    }

    if (state.authenticated) {
      enterDashboard();
    } else {
      dom.lockScreen.classList.remove("hidden");
      dom.dashboard.classList.add("hidden");
    }
  }

  async function enterDashboard() {
    clearLockoutCountdown();
    dom.lockScreen.classList.add("hidden");
    dom.dashboard.classList.remove("hidden");
    updateCloudStatusUI();
    restoreAutosaveIfEmpty();
    await refreshAdminData();
  }

  dom.loginForm.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    if (state.lockoutUntilMs > Date.now()) return;
    const pwd = dom.passwordInput.value;
    if (!pwd) return;
    if (!CRYPTO || typeof CRYPTO.sealLoginEnvelope !== "function") {
      dom.loginError.textContent = "Unable to sign in right now. Refresh and try again.";
      dom.loginError.classList.remove("hidden");
      return;
    }

    // Clear password from DOM input immediately before network call
    dom.passwordInput.value = "";
    dom.loginBtn.disabled = true;
    dom.loginBtn.textContent = "Verifying…";
    dom.loginError.classList.add("hidden");

    try {
      // Step 1: Fetch single-use signed server challenge + P-256 public key
      const challenge = await apiGet("action=challenge");
      // Step 2: End-to-end encrypt password inside ephemeral ECDH P-256 + Encrypt-then-MAC envelope
      const envelope = await CRYPTO.sealLoginEnvelope(pwd, challenge.nonce, challenge.exp, challenge.pub);
      // Step 3: Send ONLY the one-time encrypted envelope (zero plaintext & zero static hash over the wire)
      const res = await apiPost({
        action: "login",
        nonce: challenge.nonce,
        exp: challenge.exp,
        sig: challenge.sig,
        epk: envelope.epk,
        ct: envelope.ct,
        tag: envelope.tag,
      });
      state.authenticated = true;
      state.cloudConfigured = Boolean(res.cloudConfigured);
      await enterDashboard();
      showToast("Unlocked Saint Gordon Writings Admin");
    } catch (err) {
      if (err && (err.status === 404 || err.status === 403 || err.code === "GEO_BLOCKED")) {
        showNotFoundScreen();
        return;
      }
      if (err && (err.status === 429 || Number(err.retryAfter || 0) > 0)) {
        startLockoutCountdown(err.retryAfter || 5, "Incorrect password.");
        return;
      }
      dom.loginError.textContent = err.message || "Incorrect password.";
      dom.loginError.classList.remove("hidden");
      dom.loginBtn.disabled = false;
      dom.loginBtn.textContent = "Unlock Portal ↗";
      dom.passwordInput.focus();
    }
  });

  dom.btnLogout.addEventListener("click", async function () {
    try {
      await apiPost({ action: "logout" });
    } catch (_) {}
    state.authenticated = false;
    dom.dashboard.classList.add("hidden");
    dom.lockScreen.classList.remove("hidden");
    dom.passwordInput.focus();
    showToast("Signed out");
  });

  /* ========================================================================
     LOAD & RENDER POSTS + MEDIA
     ======================================================================== */
  async function refreshAdminData() {
    try {
      const data = await apiGet("action=admin_list");
      state.posts = Array.isArray(data.posts) ? data.posts : [];
      state.media = Array.isArray(data.media) ? data.media : [];
      if (typeof data.cloudConfigured === "boolean") {
        state.cloudConfigured = data.cloudConfigured;
        updateCloudStatusUI();
      }
      renderPostsList();
      renderMediaGrid();
    } catch (err) {
      if (err.message && /auth|401/i.test(err.message)) {
        state.authenticated = false;
        dom.dashboard.classList.add("hidden");
        dom.lockScreen.classList.remove("hidden");
        return;
      }
      showToast(err.message || "Could not load writings", 3500);
    }
  }

  function renderPostsList() {
    dom.tabPostsCount.textContent = String(state.posts.length);

    const filtered = state.posts.filter(function (p) {
      if (state.postFilter === "published" && (p.status || "published") !== "published") return false;
      if (state.postFilter === "draft" && p.status !== "draft") return false;
      if (state.postFilter === "pinned" && !p.pinned) return false;
      if (state.postSearch) {
        const hay = [p.title, p.summary, (p.tags || []).join(" "), p.slug].join(" ").toLowerCase();
        if (hay.indexOf(state.postSearch.toLowerCase()) === -1) return false;
      }
      return true;
    });

    if (!filtered.length) {
      dom.postsList.innerHTML =
        '<div class="writings-empty"><p>No posts match this view. Click <strong>+ New Post</strong> to start writing.</p></div>';
      return;
    }

    dom.postsList.innerHTML = filtered
      .map(function (p) {
        const isDraft = p.status === "draft";
        const tagsStr = (p.tags || []).join(" · ");
        return (
          '<div class="admin-post-row" data-slug="' +
          MD.escapeHtml(p.slug) +
          '">' +
          "<div>" +
          '<div class="admin-post-title">' +
          MD.escapeHtml(p.title) +
          "</div>" +
          '<div class="admin-post-meta micro">' +
          '<span class="admin-status-badge' +
          (isDraft ? " draft" : "") +
          '">' +
          (isDraft ? "DRAFT" : "PUBLISHED") +
          "</span>" +
          (p.pinned ? '<span class="writing-pin-badge">✳ PINNED</span>' : "") +
          "<span>" +
          MD.escapeHtml(p.date || "") +
          "</span>" +
          "<span>· " +
          (p.wordCount || 0) +
          " WORDS</span>" +
          (tagsStr ? "<span>· " + MD.escapeHtml(tagsStr) + "</span>" : "") +
          "</div>" +
          "</div>" +
          '<div class="admin-post-actions">' +
          '<button type="button" class="writings-btn writings-btn-sm" data-act="edit">Edit</button>' +
          '<a class="writings-btn writings-btn-outline writings-btn-sm" href="writing.html?slug=' +
          encodeURIComponent(p.slug) +
          '" target="_blank" rel="noopener noreferrer">View ↗</a>' +
          '<button type="button" class="writings-btn writings-btn-outline writings-btn-sm" data-act="toggle_status">' +
          (isDraft ? "Publish" : "Unpublish") +
          "</button>" +
          '<button type="button" class="writings-btn writings-btn-outline writings-btn-sm" data-act="toggle_pin">' +
          (p.pinned ? "Unpin" : "Pin") +
          "</button>" +
          '<button type="button" class="writings-btn writings-btn-danger writings-btn-sm" data-act="delete">Delete</button>' +
          "</div>" +
          "</div>"
        );
      })
      .join("");
  }

  dom.postsList.addEventListener("click", async function (ev) {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const row = btn.closest(".admin-post-row");
    const slug = row ? row.dataset.slug : "";
    const act = btn.dataset.act;
    if (!slug) return;

    if (act === "edit") {
      await openPostInEditor(slug);
      return;
    }
    if (act === "delete") {
      if (!window.confirm('Delete "' + slug + '" permanently?')) return;
      await runWriteAction(function () {
        return apiPost({ action: "delete_post", slug: slug });
      }, "Post deleted");
      return;
    }
    if (act === "toggle_status" || act === "toggle_pin") {
      await runWriteAction(function () {
        return apiPost({ action: act, slug: slug });
      }, act === "toggle_pin" ? "Updated pin state" : "Updated post status");
    }
  });

  async function runWriteAction(fn, successMsg) {
    if (!hasWriteCapability()) {
      switchTab("setup");
      showToast("Connect GITHUB_TOKEN first to save changes", 3400);
      return null;
    }
    try {
      const res = await fn();
      if (res && Array.isArray(res.posts)) {
        state.posts = res.posts;
        renderPostsList();
      }
      if (res && Array.isArray(res.media)) {
        state.media = res.media;
        renderMediaGrid();
      }
      if (successMsg) showToast(successMsg);
      return res;
    } catch (err) {
      if (err.code === "NO_GITHUB_TOKEN") {
        switchTab("setup");
      }
      showToast(err.message || "Action failed", 3800);
      return null;
    }
  }

  /* ========================================================================
     EDITOR WORKFLOW
     ======================================================================== */
  function resetEditorForNewPost() {
    state.editingOriginalSlug = "";
    state.slugManuallyEdited = false;
    dom.edTitle.value = "";
    dom.edSlug.value = "";
    dom.edDate.value = todayIso();
    dom.edTags.value = "";
    dom.edStatus.value = "published";
    dom.edPinned.checked = false;
    dom.edSummary.value = "";
    dom.edCover.value = "";
    dom.edBody.value = "";
    updateCoverPreview();
    updatePreviewAndStats();
    switchTab("editor");
    dom.edTitle.focus();
  }

  async function openPostInEditor(slug) {
    showToast("Loading entry…", 1500);
    try {
      const data = await apiGet("action=post&slug=" + encodeURIComponent(slug));
      const p = data.post || {};
      state.editingOriginalSlug = p.slug || slug;
      state.slugManuallyEdited = true;
      dom.edTitle.value = p.title || "";
      dom.edSlug.value = p.slug || slug;
      dom.edDate.value = (p.date || todayIso()).slice(0, 10);
      dom.edTags.value = (p.tags || []).join(", ");
      dom.edStatus.value = p.status === "draft" ? "draft" : "published";
      dom.edPinned.checked = Boolean(p.pinned);
      dom.edSummary.value = p.summary || "";
      dom.edCover.value = p.coverImage || "";
      dom.edBody.value = data.body || "";
      updateCoverPreview();
      updatePreviewAndStats();
      switchTab("editor");
    } catch (err) {
      showToast(err.message || "Could not open post", 3200);
    }
  }

  function updateCoverPreview() {
    const raw = dom.edCover.value.trim();
    const media = MD.resolveMediaSrc(raw);
    if (media.primary) {
      dom.edCoverPreview.src = media.primary;
      dom.edCoverPreview.classList.remove("hidden");
      dom.btnClearCover.classList.remove("hidden");
    } else {
      dom.edCoverPreview.classList.add("hidden");
      dom.btnClearCover.classList.add("hidden");
    }
  }

  function updatePreviewAndStats() {
    const body = dom.edBody.value || "";
    const plain = MD.stripMarkdown(body);
    const words = plain ? plain.split(/\s+/).filter(Boolean).length : 0;
    const mins = Math.max(1, Math.round(words / 210));
    dom.edStats.textContent = words + " WORDS · " + mins + " MIN READ";

    const titleHtml = dom.edTitle.value.trim()
      ? '<h1 class="writing-title" style="font-size:2.4rem;margin-bottom:12px;">' +
        MD.escapeHtml(dom.edTitle.value.trim()) +
        "</h1>"
      : "";
    const sumHtml = dom.edSummary.value.trim()
      ? '<p class="writing-lead" style="margin-bottom:24px;">' + MD.escapeHtml(dom.edSummary.value.trim()) + "</p>"
      : "";
    dom.edPreview.innerHTML =
      titleHtml +
      sumHtml +
      (body.trim()
        ? MD.renderMarkdown(body)
        : '<p style="color:#777777;font-style:italic;">Live preview appears here as you write…</p>');
    MD.attachMediaFallbacks(dom.edPreview);
  }

  function saveLocalAutosave() {
    try {
      const payload = {
        originalSlug: state.editingOriginalSlug,
        title: dom.edTitle.value,
        slug: dom.edSlug.value,
        date: dom.edDate.value,
        tags: dom.edTags.value,
        status: dom.edStatus.value,
        pinned: dom.edPinned.checked,
        summary: dom.edSummary.value,
        coverImage: dom.edCover.value,
        body: dom.edBody.value,
        savedAt: Date.now(),
      };
      window.localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(payload));
      dom.edAutosaveStatus.textContent = "AUTOSAVED LOCALLY";
    } catch (_) {}
  }

  function restoreAutosaveIfEmpty() {
    try {
      const raw = window.localStorage.getItem(DRAFT_STORAGE_KEY);
      if (!raw) {
        dom.edDate.value = todayIso();
        updatePreviewAndStats();
        return;
      }
      const d = JSON.parse(raw);
      state.editingOriginalSlug = d.originalSlug || "";
      dom.edTitle.value = d.title || "";
      dom.edSlug.value = d.slug || "";
      dom.edDate.value = d.date || todayIso();
      dom.edTags.value = d.tags || "";
      dom.edStatus.value = d.status || "published";
      dom.edPinned.checked = Boolean(d.pinned);
      dom.edSummary.value = d.summary || "";
      dom.edCover.value = d.coverImage || "";
      dom.edBody.value = d.body || "";
      state.slugManuallyEdited = Boolean(d.slug);
      updateCoverPreview();
      updatePreviewAndStats();
    } catch (_) {
      dom.edDate.value = todayIso();
    }
  }

  dom.edTitle.addEventListener("input", function () {
    if (!state.slugManuallyEdited && !state.editingOriginalSlug) {
      dom.edSlug.value = MD.slugify(dom.edTitle.value);
    }
    updatePreviewAndStats();
    saveLocalAutosave();
  });

  dom.edSlug.addEventListener("input", function () {
    state.slugManuallyEdited = Boolean(dom.edSlug.value.trim());
    saveLocalAutosave();
  });

  [dom.edDate, dom.edTags, dom.edStatus, dom.edPinned, dom.edSummary, dom.edBody].forEach(function (el) {
    const sync = function () {
      updatePreviewAndStats();
      saveLocalAutosave();
    };
    el.addEventListener("input", sync);
    el.addEventListener("change", sync);
  });

  dom.edCover.addEventListener("input", function () {
    updateCoverPreview();
    saveLocalAutosave();
  });

  dom.btnClearCover.addEventListener("click", function () {
    dom.edCover.value = "";
    updateCoverPreview();
    saveLocalAutosave();
  });

  // Quick tag preset chips
  document.getElementById("ed-quick-tags").addEventListener("click", function (ev) {
    const btn = ev.target.closest("button[data-add-tag]");
    if (!btn) return;
    const tag = btn.dataset.addTag;
    const existing = dom.edTags.value
      .split(",")
      .map(function (s) { return s.trim(); })
      .filter(Boolean);
    if (!existing.some(function (t) { return t.toLowerCase() === tag.toLowerCase(); })) {
      existing.push(tag);
      dom.edTags.value = existing.join(", ");
      saveLocalAutosave();
    }
  });

  // Editor view mode switcher (Split / Write / Preview)
  document.querySelectorAll("button[data-view-mode]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const mode = btn.dataset.viewMode;
      state.viewMode = mode;
      document.querySelectorAll("button[data-view-mode]").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      dom.editorWorkspace.className = "editor-workspace mode-" + mode;
      dom.edBody.classList.toggle("hidden", mode === "preview");
      dom.edPreview.classList.toggle("hidden", mode === "write");
      updatePreviewAndStats();
    });
  });

  // Markdown toolbar insertion helpers
  function insertAtCursor(before, after, placeholder) {
    const ta = dom.edBody;
    const start = ta.selectionStart || 0;
    const end = ta.selectionEnd || 0;
    const selected = ta.value.slice(start, end) || placeholder || "";
    const insertion = before + selected + (after || "");
    ta.value = ta.value.slice(0, start) + insertion + ta.value.slice(end);
    const cursorPos = start + before.length + selected.length + (after ? after.length : 0);
    ta.focus();
    ta.setSelectionRange(cursorPos, cursorPos);
    updatePreviewAndStats();
    saveLocalAutosave();
  }

  document.querySelectorAll("button[data-md]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const kind = btn.dataset.md;
      if (kind === "h2") insertAtCursor("\n## ", "\n", "Section Heading");
      else if (kind === "h3") insertAtCursor("\n### ", "\n", "Subheading");
      else if (kind === "bold") insertAtCursor("**", "**", "bold text");
      else if (kind === "italic") insertAtCursor("*", "*", "italic text");
      else if (kind === "quote") insertAtCursor("\n> ", "\n", "Pull quote here");
      else if (kind === "ul") insertAtCursor("\n- ", "\n", "List item");
      else if (kind === "ol") insertAtCursor("\n1. ", "\n", "First step");
      else if (kind === "code") insertAtCursor("\n```\n", "\n```\n", "code or settings");
      else if (kind === "hr") insertAtCursor("\n\n---\n\n", "", "");
      else if (kind === "link") {
        const url = window.prompt("Enter link URL (https://...):", "https://");
        if (url && url.trim()) insertAtCursor("[", "](" + url.trim() + ")", "link text");
      }
    });
  });

  // Save / Publish Post
  async function submitPost(forceStatus) {
    const title = dom.edTitle.value.trim();
    if (!title) {
      showToast("Add a post title first", 2600);
      dom.edTitle.focus();
      return;
    }
    const status = forceStatus || dom.edStatus.value || "published";
    dom.edStatus.value = status;
    const slug = MD.slugify(dom.edSlug.value || title);
    dom.edSlug.value = slug;

    dom.btnPublishPost.disabled = true;
    dom.btnSaveDraft.disabled = true;
    const origPubText = dom.btnPublishPost.textContent;
    dom.btnPublishPost.textContent = status === "published" ? "Publishing…" : "Saving…";

    try {
      const res = await runWriteAction(
        function () {
          return apiPost({
            action: "save_post",
            originalSlug: state.editingOriginalSlug,
            title: title,
            slug: slug,
            date: dom.edDate.value || todayIso(),
            tags: dom.edTags.value,
            status: status,
            pinned: dom.edPinned.checked,
            summary: dom.edSummary.value.trim(),
            coverImage: dom.edCover.value.trim(),
            body: dom.edBody.value,
          });
        },
        status === "published" ? "Published live to Writings!" : "Saved as draft"
      );

      if (res && res.ok) {
        state.editingOriginalSlug = res.post.slug;
        state.slugManuallyEdited = true;
        try { window.localStorage.removeItem(DRAFT_STORAGE_KEY); } catch (_) {}
        dom.edAutosaveStatus.textContent = status === "published" ? "PUBLISHED TO GITHUB" : "SAVED AS DRAFT";
      }
    } finally {
      dom.btnPublishPost.disabled = false;
      dom.btnSaveDraft.disabled = false;
      dom.btnPublishPost.textContent = origPubText;
    }
  }

  dom.btnPublishPost.addEventListener("click", function () { submitPost("published"); });
  dom.btnSaveDraft.addEventListener("click", function () { submitPost("draft"); });

  dom.btnDownloadMd.addEventListener("click", function () {
    const title = dom.edTitle.value.trim() || "untitled-entry";
    const slug = MD.slugify(dom.edSlug.value || title) || "entry";
    const tags = dom.edTags.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    const fm = [
      "---",
      "title: " + JSON.stringify(title),
      "slug: " + JSON.stringify(slug),
      "date: " + JSON.stringify(dom.edDate.value || todayIso()),
      "status: " + JSON.stringify(dom.edStatus.value || "published"),
      "pinned: " + (dom.edPinned.checked ? "true" : "false"),
      "tags: " + JSON.stringify(tags),
      "summary: " + JSON.stringify(dom.edSummary.value.trim()),
      "coverImage: " + JSON.stringify(dom.edCover.value.trim()),
      "---",
      "",
      dom.edBody.value,
      "",
    ].join("\n");
    const blob = new Blob([fm], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = slug + ".md";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    showToast("Downloaded " + slug + ".md");
  });

  /* ========================================================================
     IMAGE OPTIMIZER (WITH OPTIONAL SAINT GORDON XEROX FILTER) & MEDIA UPLOAD
     ======================================================================== */
  function readFileAsBase64(file) {
    return new Promise(function (resolve, reject) {
      const reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result || "")); };
      reader.onerror = function () { reject(new Error("Could not read file.")); };
      reader.readAsDataURL(file);
    });
  }

  async function processImageBeforeUpload(file, { compress = true, xerox = false } = {}) {
    if (!file.type.startsWith("image/") || file.type === "image/gif") {
      return {
        filename: file.name,
        dataBase64: await readFileAsBase64(file),
      };
    }
    if (!compress && !xerox && file.size <= 3_500_000) {
      return {
        filename: file.name,
        dataBase64: await readFileAsBase64(file),
      };
    }

    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      img.decoding = "async";
      await new Promise(function (resolve, reject) {
        img.onload = resolve;
        img.onerror = function () { reject(new Error("Could not decode image.")); };
        img.src = url;
      });

      const maxEdge = 1800;
      let w = img.naturalWidth || img.width;
      let h = img.naturalHeight || img.height;
      if (compress && Math.max(w, h) > maxEdge) {
        const scale = maxEdge / Math.max(w, h);
        w = Math.max(1, Math.round(w * scale));
        h = Math.max(1, Math.round(h * scale));
      }

      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, w, h);
      ctx.drawImage(img, 0, 0, w, h);

      if (xerox) {
        const imgData = ctx.getImageData(0, 0, w, h);
        const px = imgData.data;
        let seed = 1337;
        const thresh = 105 / 255;
        const grainAmp = 60 / 255;
        for (let i = 0; i < px.length; i += 4) {
          let u = (0.2126 * px[i] + 0.7152 * px[i + 1] + 0.0722 * px[i + 2]) / 255;
          if (u > 0.196 && u < 0.941) {
            seed ^= seed << 13;
            seed ^= seed >>> 17;
            seed ^= seed << 5;
            u -= ((seed >>> 0) / 4294967296) * grainAmp;
          }
          const v = u >= thresh ? 255 : 0;
          px[i] = v;
          px[i + 1] = v;
          px[i + 2] = v;
        }
        ctx.putImageData(imgData, 0, 0);
      }

      const mime = xerox ? "image/png" : "image/jpeg";
      const ext = xerox ? ".png" : ".jpg";
      const stem = file.name.replace(/\.[^.]+$/, "");
      const outName = xerox ? stem + "-xerox" + ext : stem + ext;
      const dataUrl = canvas.toDataURL(mime, xerox ? undefined : 0.88);
      return { filename: outName, dataBase64: dataUrl };
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  async function uploadSingleFile(file, opts) {
    if (!hasWriteCapability()) {
      switchTab("setup");
      showToast("Connect GITHUB_TOKEN first to upload media", 3400);
      return null;
    }
    showToast("Uploading " + file.name + "…", 4000);
    let prepared;
    try {
      prepared = await processImageBeforeUpload(file, opts || { compress: true, xerox: false });
    } catch (err) {
      showToast((err && err.message) || "Could not process file for upload", 3800);
      return null;
    }
    const res = await runWriteAction(function () {
      return apiPost({
        action: "upload_media",
        filename: prepared.filename,
        dataBase64: prepared.dataBase64,
      });
    }, "Uploaded " + prepared.filename);
    if (res && res.media) {
      state.media.unshift(res.media);
      renderMediaGrid();
      return res.media;
    }
    return null;
  }

  // Cover upload
  dom.btnUploadCover.addEventListener("click", function () { dom.edCoverFile.click(); });
  dom.edCoverFile.addEventListener("change", async function () {
    const file = dom.edCoverFile.files && dom.edCoverFile.files[0];
    dom.edCoverFile.value = "";
    if (!file) return;
    const uploaded = await uploadSingleFile(file, {
      compress: true,
      xerox: dom.edCoverXerox.checked,
    });
    if (uploaded) {
      dom.edCover.value = uploaded.path;
      updateCoverPreview();
      saveLocalAutosave();
    }
  });

  // Inline image upload button
  dom.btnInsertImage.addEventListener("click", function () { dom.edInlineImageFile.click(); });
  dom.edInlineImageFile.addEventListener("change", async function () {
    const file = dom.edInlineImageFile.files && dom.edInlineImageFile.files[0];
    dom.edInlineImageFile.value = "";
    if (!file) return;
    const uploaded = await uploadSingleFile(file, { compress: true, xerox: false });
    if (uploaded) {
      insertAtCursor("\n" + uploaded.markdown + "\n", "", "");
    }
  });

  // Drag & drop image directly into Markdown editor!
  dom.edBody.addEventListener("dragover", function (ev) {
    ev.preventDefault();
    dom.edBody.classList.add("drag-over");
  });
  dom.edBody.addEventListener("dragleave", function () {
    dom.edBody.classList.remove("drag-over");
  });
  dom.edBody.addEventListener("drop", async function (ev) {
    const files = ev.dataTransfer && ev.dataTransfer.files;
    if (!files || !files.length) return;
    ev.preventDefault();
    dom.edBody.classList.remove("drag-over");
    for (let i = 0; i < files.length; i++) {
      const uploaded = await uploadSingleFile(files[i], { compress: true, xerox: false });
      if (uploaded) {
        insertAtCursor("\n" + uploaded.markdown + "\n", "", "");
      }
    }
  });

  // Video / Embed modal
  dom.btnInsertVideo.addEventListener("click", function () {
    dom.embedUrlInput.value = "";
    dom.embedCaptionInput.value = "";
    dom.embedModal.classList.remove("hidden");
    dom.embedUrlInput.focus();
  });
  dom.btnEmbedCancel.addEventListener("click", function () { dom.embedModal.classList.add("hidden"); });
  dom.embedModal.addEventListener("click", function (ev) {
    if (ev.target === dom.embedModal) dom.embedModal.classList.add("hidden");
  });
  dom.btnEmbedInsert.addEventListener("click", function () {
    const url = dom.embedUrlInput.value.trim();
    const cap = dom.embedCaptionInput.value.trim();
    if (!url) {
      showToast("Paste a YouTube, Vimeo, SoundCloud, or video URL");
      return;
    }
    const line = cap ? "\n![" + cap + "](" + url + ")\n" : "\n" + url + "\n";
    dom.embedModal.classList.add("hidden");
    insertAtCursor(line, "", "");
  });
  dom.btnUploadClip.addEventListener("click", function () { dom.embedVideoFile.click(); });
  dom.embedVideoFile.addEventListener("change", async function () {
    const file = dom.embedVideoFile.files && dom.embedVideoFile.files[0];
    dom.embedVideoFile.value = "";
    if (!file) return;
    if (file.size > 3_000_000) {
      showToast("Clip is over 3 MB — upload to YouTube/Vimeo and paste the link instead!", 4200);
      return;
    }
    dom.embedModal.classList.add("hidden");
    const uploaded = await uploadSingleFile(file, { compress: false, xerox: false });
    if (uploaded) {
      insertAtCursor("\n" + uploaded.markdown + "\n", "", "");
    }
  });

  /* ========================================================================
     MEDIA LIBRARY VIEW
     ======================================================================== */
  function renderMediaGrid() {
    dom.tabMediaCount.textContent = String(state.media.length);
    if (!state.media.length) {
      dom.mediaGrid.innerHTML = '<div class="writings-empty" style="grid-column:1/-1;"><p>No uploaded media yet. Drop photos or short clips above.</p></div>';
      return;
    }
    dom.mediaGrid.innerHTML = state.media
      .map(function (item) {
        const previewSrc = item.liveUrl || item.path;
        let thumb = "";
        if (item.kind === "video") {
          thumb = '<video src="' + MD.escapeHtml(previewSrc) + '" muted preload="metadata"></video>';
        } else if (item.kind === "audio") {
          thumb = '<span class="micro" style="color:#f2f2f2;">♪ AUDIO FILE</span>';
        } else {
          thumb = '<img src="' + MD.escapeHtml(previewSrc) + '" alt="' + MD.escapeHtml(item.filename) + '" loading="lazy" />';
        }
        const kb = item.size ? (item.size / 1024).toFixed(0) + " KB" : "";
        return (
          '<div class="media-item" data-file="' +
          MD.escapeHtml(item.filename) +
          '" data-path="' +
          MD.escapeHtml(item.path) +
          '">' +
          '<div class="media-thumb-box">' +
          thumb +
          "</div>" +
          '<div class="media-item-body">' +
          '<div class="media-name">' +
          MD.escapeHtml(item.filename) +
          (kb ? " · " + kb : "") +
          "</div>" +
          '<div class="media-item-actions">' +
          '<button type="button" class="writings-btn writings-btn-sm" data-mact="insert">Insert</button>' +
          (item.kind === "image"
            ? '<button type="button" class="writings-btn writings-btn-outline writings-btn-sm" data-mact="cover">Cover</button>'
            : "") +
          '<button type="button" class="writings-btn writings-btn-outline writings-btn-sm" data-mact="copy">Copy MD</button>' +
          '<button type="button" class="writings-btn writings-btn-danger writings-btn-sm" data-mact="delete">×</button>' +
          "</div>" +
          "</div>" +
          "</div>"
        );
      })
      .join("");
  }

  dom.btnMediaPick.addEventListener("click", function () { dom.mediaUploadInput.click(); });
  dom.mediaUploadInput.addEventListener("change", async function () {
    const files = Array.from(dom.mediaUploadInput.files || []);
    dom.mediaUploadInput.value = "";
    for (let i = 0; i < files.length; i++) {
      await uploadSingleFile(files[i], {
        compress: dom.mediaOptCompress.checked,
        xerox: dom.mediaOptXerox.checked,
      });
    }
  });
  dom.mediaDropzone.addEventListener("dragover", function (ev) {
    ev.preventDefault();
    dom.mediaDropzone.classList.add("drag-over");
  });
  dom.mediaDropzone.addEventListener("dragleave", function () {
    dom.mediaDropzone.classList.remove("drag-over");
  });
  dom.mediaDropzone.addEventListener("drop", async function (ev) {
    ev.preventDefault();
    dom.mediaDropzone.classList.remove("drag-over");
    const files = Array.from((ev.dataTransfer && ev.dataTransfer.files) || []);
    for (let i = 0; i < files.length; i++) {
      await uploadSingleFile(files[i], {
        compress: dom.mediaOptCompress.checked,
        xerox: dom.mediaOptXerox.checked,
      });
    }
  });

  dom.mediaGrid.addEventListener("click", async function (ev) {
    const btn = ev.target.closest("button[data-mact]");
    if (!btn) return;
    const card = btn.closest(".media-item");
    const file = card ? card.dataset.file : "";
    const path = card ? card.dataset.path : "";
    const act = btn.dataset.mact;
    const md = "![" + file.replace(/\.[^.]+$/, "") + "](" + path + ")";

    if (act === "insert") {
      switchTab("editor");
      insertAtCursor("\n" + md + "\n", "", "");
      showToast("Inserted into editor");
    } else if (act === "cover") {
      dom.edCover.value = path;
      updateCoverPreview();
      saveLocalAutosave();
      switchTab("editor");
      showToast("Set as post cover");
    } else if (act === "copy") {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(md).then(function () { showToast("Copied Markdown snippet"); });
      }
    } else if (act === "delete") {
      if (!window.confirm('Delete "' + file + '" from media library?')) return;
      await runWriteAction(function () {
        return apiPost({ action: "delete_media", filename: file });
      }, "Deleted media file");
    }
  });

  /* ========================================================================
     GLOBAL CONTROLS & SETUP TAB
     ======================================================================== */
  document.querySelectorAll(".admin-tab").forEach(function (btn) {
    btn.addEventListener("click", function () { switchTab(btn.dataset.tab); });
  });
  dom.cloudStatusBtn.addEventListener("click", function () { switchTab("setup"); });
  dom.btnNewPost.addEventListener("click", resetEditorForNewPost);
  dom.btnRefreshPosts.addEventListener("click", function () {
    refreshAdminData().then(function () { showToast("Refreshed from GitHub"); });
  });

  document.querySelectorAll("button[data-post-filter]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      state.postFilter = btn.dataset.postFilter || "all";
      document.querySelectorAll("button[data-post-filter]").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      renderPostsList();
    });
  });

  dom.postsSearch.addEventListener("input", function () {
    state.postSearch = dom.postsSearch.value.trim();
    renderPostsList();
  });

  dom.btnSaveBrowserToken.addEventListener("click", function () {
    const val = dom.setupBrowserToken.value.trim();
    if (!val) {
      showToast("Paste a GitHub token first");
      return;
    }
    try { window.localStorage.setItem(TOKEN_STORAGE_KEY, val); } catch (_) {}
    updateCloudStatusUI();
    refreshAdminData();
    showToast("Saved scoped GitHub token in this browser");
  });

  dom.btnClearBrowserToken.addEventListener("click", function () {
    try { window.localStorage.removeItem(TOKEN_STORAGE_KEY); } catch (_) {}
    dom.setupBrowserToken.value = "";
    updateCloudStatusUI();
    showToast("Cleared browser token");
  });

  checkSession();
})();
