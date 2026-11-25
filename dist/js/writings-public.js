/* Saint Gordon Collective — Public Writings Reader & Search Controller */
(function () {
  "use strict";

  const MD = window.SaintWritingsMarkdown;
  if (!MD) return;

  const pageType = document.body.dataset.page;
  const API_BASE = "/api/writings";

  function sortPosts(posts, order) {
    const list = posts.slice();
    list.sort(function (a, b) {
      if (order === "newest") {
        const pinDiff = (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0);
        if (pinDiff !== 0) return pinDiff;
        const dateDiff = String(b.date || "").localeCompare(String(a.date || ""));
        if (dateDiff !== 0) return dateDiff;
        return String(b.updatedAt || "").localeCompare(String(a.updatedAt || ""));
      }
      const dateDiff = String(a.date || "").localeCompare(String(b.date || ""));
      if (dateDiff !== 0) return dateDiff;
      return String(a.updatedAt || "").localeCompare(String(b.updatedAt || ""));
    });
    return list;
  }

  async function fetchPublishedPosts() {
    // Prefer live Vercel API (sees brand-new posts immediately before rebuild), fallback to static JSON
    try {
      const resp = await fetch(API_BASE + "?action=list", { credentials: "same-origin" });
      if (resp.ok) {
        const data = await resp.json();
        if (Array.isArray(data.posts)) return data.posts;
      }
    } catch (_) {
      // Static fallback below
    }
    try {
      const resp = await fetch("writings/posts.json");
      if (resp.ok) {
        const data = await resp.json();
        if (Array.isArray(data)) {
          return data.filter(function (p) {
            return (p.status || "published") === "published";
          });
        }
      }
    } catch (_) {
      // Ignore
    }
    return [];
  }

  async function fetchSinglePost(slug) {
    try {
      const resp = await fetch(API_BASE + "?action=post&slug=" + encodeURIComponent(slug), {
        credentials: "same-origin",
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.post) return data;
      }
    } catch (_) {
      // Fallback below
    }
    try {
      const [indexResp, mdResp] = await Promise.all([
        fetch("writings/posts.json"),
        fetch("writings/posts/" + encodeURIComponent(slug) + ".md"),
      ]);
      if (!mdResp.ok) return null;
      const rawMd = await mdResp.text();
      const body = rawMd.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/, "").trim();
      let meta = { slug: slug, title: slug };
      if (indexResp.ok) {
        const list = await indexResp.json();
        const found = Array.isArray(list) ? list.find(function (p) { return p.slug === slug; }) : null;
        if (found) meta = found;
      }
      return { post: meta, body: body };
    } catch (_) {
      return null;
    }
  }

  function coverImgHtml(coverImage, title, className) {
    if (!coverImage) return "";
    const media = MD.resolveMediaSrc(coverImage);
    if (!media.primary) return "";
    const fbAttr = media.fallback ? ' data-fallback-src="' + MD.escapeHtml(media.fallback) + '"' : "";
    return (
      '<div class="' +
      className +
      '">' +
      '<img src="' +
      MD.escapeHtml(media.primary) +
      '" alt="' +
      MD.escapeHtml(title || "Cover image") +
      '" loading="lazy"' +
      fbAttr +
      " />" +
      "</div>"
    );
  }

  /* ========================================================================
     PUBLIC WRITINGS INDEX (writings.html)
     ======================================================================== */
  if (pageType === "writings") {
    const state = {
      posts: [],
      query: "",
      tag: "all",
      sort: "newest",
    };

    const feedEl = document.getElementById("writings-feed");
    const searchInput = document.getElementById("writings-search-input");
    const clearBtn = document.getElementById("writings-search-clear");
    const tagContainer = document.getElementById("writings-tag-filters");
    const countEl = document.getElementById("writings-result-count");
    const sortBtns = document.querySelectorAll(".writings-seg-btn");

    // Read optional ?q= or ?tag= query params
    try {
      const params = new URLSearchParams(window.location.search);
      if (params.get("q")) {
        state.query = params.get("q").trim();
        if (searchInput) searchInput.value = state.query;
      }
      if (params.get("tag")) {
        state.tag = params.get("tag").trim();
      }
    } catch (_) {}

    function renderTags() {
      if (!tagContainer) return;
      const counts = new Map();
      state.posts.forEach(function (post) {
        (post.tags || []).forEach(function (t) {
          counts.set(t, (counts.get(t) || 0) + 1);
        });
      });

      const pills = [
        '<button type="button" class="writings-tag-pill micro' +
          (state.tag === "all" ? " active" : "") +
          '" data-tag="all">All (' +
          state.posts.length +
          ")</button>",
      ];
      Array.from(counts.keys())
        .sort()
        .forEach(function (tag) {
          const active = state.tag.toLowerCase() === tag.toLowerCase();
          pills.push(
            '<button type="button" class="writings-tag-pill micro' +
              (active ? " active" : "") +
              '" data-tag="' +
              MD.escapeHtml(tag) +
              '">' +
              MD.escapeHtml(tag) +
              " (" +
              counts.get(tag) +
              ")</button>"
          );
        });
      tagContainer.innerHTML = pills.join("");
    }

    function matchesQuery(post, q) {
      if (!q) return true;
      const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
      const haystack = [
        post.title || "",
        post.summary || "",
        (post.tags || []).join(" "),
        post.searchText || "",
        post.date || "",
      ]
        .join(" ")
        .toLowerCase();
      return terms.every(function (term) {
        return haystack.indexOf(term) !== -1;
      });
    }

    function renderFeed() {
      if (!feedEl) return;
      if (clearBtn) clearBtn.classList.toggle("hidden", !state.query);

      const filtered = sortPosts(
        state.posts.filter(function (post) {
          if (state.tag !== "all") {
            const hasTag = (post.tags || []).some(function (t) {
              return t.toLowerCase() === state.tag.toLowerCase();
            });
            if (!hasTag) return false;
          }
          return matchesQuery(post, state.query);
        }),
        state.sort
      );

      if (countEl) {
        const label = filtered.length === 1 ? "1 ENTRY" : filtered.length + " ENTRIES";
        countEl.textContent =
          state.query || state.tag !== "all"
            ? label + " MATCHED"
            : label;
      }

      if (!filtered.length) {
        feedEl.innerHTML =
          '<div class="writings-empty">' +
          '<span class="micro">NO ENTRIES FOUND</span>' +
          "<h2>Nothing matched that filter.</h2>" +
          "<p>" +
          (state.posts.length
            ? "Try a different keyword or switch back to All tags."
            : "No writings have been published yet. Sign in to the Admin portal to write the first entry.") +
          "</p>" +
          (state.query || state.tag !== "all"
            ? '<button type="button" id="btn-reset-writings-filters" class="writings-btn">Reset Search &amp; Filters</button>'
            : "") +
          "</div>";
        const resetBtn = document.getElementById("btn-reset-writings-filters");
        if (resetBtn) {
          resetBtn.addEventListener("click", function () {
            state.query = "";
            state.tag = "all";
            if (searchInput) searchInput.value = "";
            renderTags();
            renderFeed();
          });
        }
        return;
      }

      const showFeatured = !state.query && state.tag === "all" && state.sort === "newest";
      const htmlParts = [];

      filtered.forEach(function (post, idx) {
        const href = "writing.html?slug=" + encodeURIComponent(post.slug);
        const dateLabel = MD.formatDisplayDate(post.date);
        const readMin = post.readingTimeMin || 1;
        const tagsHtml = (post.tags || [])
          .map(function (t) {
            return '<span class="writing-chip micro">' + MD.escapeHtml(t) + "</span>";
          })
          .join("");
        const pinBadge = post.pinned ? '<span class="writing-pin-badge micro">✳ PINNED</span>' : "";

        if (showFeatured && idx === 0) {
          htmlParts.push(
            '<article class="writing-featured-card">' +
              '<div class="writing-card-top micro">' +
              "<span>" +
              (post.pinned ? "✳ PINNED ENTRY" : "LATEST ENTRY") +
              "</span>" +
              "<span>" +
              MD.escapeHtml(dateLabel) +
              " · " +
              readMin +
              " MIN READ</span>" +
              "</div>" +
              '<div class="writing-featured-grid' +
              (post.coverImage ? " has-cover" : "") +
              '">' +
              coverImgHtml(post.coverImage, post.title, "writing-featured-cover") +
              '<div class="writing-featured-copy">' +
              '<h2><a href="' +
              href +
              '">' +
              MD.escapeHtml(post.title) +
              "</a></h2>" +
              '<p class="writing-summary">' +
              MD.escapeHtml(post.summary || "") +
              "</p>" +
              (tagsHtml ? '<div class="writing-chips">' + tagsHtml + "</div>" : "") +
              '<a class="paper-button writing-read-cta" href="' +
              href +
              '">Read Entry <span aria-hidden="true">↗</span></a>' +
              "</div>" +
              "</div>" +
              "</article>"
          );
        } else {
          htmlParts.push(
            '<article class="writing-list-item' +
              (post.coverImage ? " has-cover" : "") +
              '">' +
              coverImgHtml(post.coverImage, post.title, "writing-list-thumb") +
              '<div class="writing-list-body">' +
              '<div class="writing-list-meta micro">' +
              pinBadge +
              "<span>" +
              MD.escapeHtml(dateLabel) +
              "</span>" +
              "<span>· " +
              readMin +
              " MIN READ</span>" +
              "</div>" +
              '<h3><a href="' +
              href +
              '">' +
              MD.escapeHtml(post.title) +
              "</a></h3>" +
              '<p class="writing-list-summary">' +
              MD.escapeHtml(post.summary || "") +
              "</p>" +
              '<div class="writing-list-foot">' +
              '<div class="writing-chips">' +
              tagsHtml +
              "</div>" +
              '<a class="writing-list-link micro" href="' +
              href +
              '">Read ↗</a>' +
              "</div>" +
              "</div>" +
              "</article>"
          );
        }
      });

      feedEl.innerHTML = htmlParts.join("");
      MD.attachMediaFallbacks(feedEl);
    }

    if (searchInput) {
      searchInput.addEventListener("input", function () {
        state.query = searchInput.value.trim();
        renderFeed();
      });
    }
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        state.query = "";
        if (searchInput) {
          searchInput.value = "";
          searchInput.focus();
        }
        renderFeed();
      });
    }
    if (tagContainer) {
      tagContainer.addEventListener("click", function (ev) {
        const btn = ev.target.closest("button[data-tag]");
        if (!btn) return;
        state.tag = btn.dataset.tag || "all";
        renderTags();
        renderFeed();
      });
    }
    sortBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.sort = btn.dataset.sort || "newest";
        sortBtns.forEach(function (b) {
          b.classList.toggle("active", b === btn);
        });
        renderFeed();
      });
    });

    fetchPublishedPosts().then(function (posts) {
      state.posts = posts;
      renderTags();
      renderFeed();
    });
  }

  /* ========================================================================
     SINGLE ENTRY READER (writing.html)
     ======================================================================== */
  if (pageType === "writing") {
    const articleEl = document.getElementById("writing-article");
    const prevNextEl = document.getElementById("writing-prev-next");
    const copyLinkBtn = document.getElementById("btn-copy-post-link");
    const toastEl = document.getElementById("writing-toast");

    function showToast(msg) {
      if (!toastEl) return;
      toastEl.textContent = msg;
      toastEl.classList.remove("hidden");
      clearTimeout(showToast._t);
      showToast._t = setTimeout(function () {
        toastEl.classList.add("hidden");
      }, 2400);
    }

    if (copyLinkBtn) {
      copyLinkBtn.addEventListener("click", function () {
        const href = window.location.href;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(href).then(function () {
            showToast("Copied link to clipboard");
          }).catch(function () {
            showToast("Copy from address bar");
          });
        } else {
          showToast("Copy from address bar");
        }
      });
    }

    const params = new URLSearchParams(window.location.search);
    const slug = MD.slugify(params.get("slug") || "");

    if (!slug) {
      if (articleEl) {
        articleEl.innerHTML =
          '<div class="writings-empty"><h2>Entry not specified.</h2><p><a class="text-link" href="writings.html">Return to Writings ↗</a></p></div>';
      }
      return;
    }

    Promise.all([fetchSinglePost(slug), fetchPublishedPosts()]).then(function (res) {
      const data = res[0];
      const allPosts = sortPosts(res[1] || [], "newest");

      if (!data || !data.post) {
        if (articleEl) {
          articleEl.innerHTML =
            '<div class="writings-empty"><span class="micro">404 / NOT FOUND</span><h2>This entry could not be found.</h2><p>It may have been moved, renamed, or set to draft.</p><a class="text-link" href="writings.html">← Browse all Writings</a></div>';
        }
        return;
      }

      const post = data.post;
      document.title = post.title + " — Saint Gordon Writings";

      const dateLabel = MD.formatDisplayDate(post.date);
      const readMin = post.readingTimeMin || MD.estimateReadingTime(data.body);
      const tagsHtml = (post.tags || [])
        .map(function (t) {
          return (
            '<a class="writing-chip micro" href="writings.html?tag=' +
            encodeURIComponent(t) +
            '">' +
            MD.escapeHtml(t) +
            "</a>"
          );
        })
        .join("");

      const draftNotice =
        post.status === "draft"
          ? '<div class="writing-draft-banner micro">DRAFT PREVIEW — NOT VISIBLE TO PUBLIC READERS</div>'
          : "";

      if (articleEl) {
        articleEl.innerHTML =
          draftNotice +
          '<header class="writing-header">' +
          '<div class="writing-header-meta micro">' +
          (post.pinned ? '<span class="writing-pin-badge">✳ PINNED</span>' : "") +
          "<span>" +
          MD.escapeHtml(dateLabel) +
          "</span>" +
          "<span>· " +
          readMin +
          " MIN READ</span>" +
          "</div>" +
          '<h1 class="writing-title">' +
          MD.escapeHtml(post.title) +
          "</h1>" +
          (post.summary ? '<p class="writing-lead">' + MD.escapeHtml(post.summary) + "</p>" : "") +
          (tagsHtml ? '<div class="writing-chips">' + tagsHtml + "</div>" : "") +
          "</header>" +
          coverImgHtml(post.coverImage, post.title, "writing-hero-cover") +
          '<div class="writing-prose">' +
          MD.renderMarkdown(data.body || "") +
          "</div>";

        MD.attachMediaFallbacks(articleEl);
      }

      // Render Previous / Next navigation
      if (prevNextEl && allPosts.length > 1) {
        const idx = allPosts.findIndex(function (p) {
          return p.slug === post.slug;
        });
        if (idx !== -1) {
          const newer = idx > 0 ? allPosts[idx - 1] : null;
          const older = idx < allPosts.length - 1 ? allPosts[idx + 1] : null;
          if (newer || older) {
            prevNextEl.innerHTML =
              (newer
                ? '<a class="writing-adj-card" href="writing.html?slug=' +
                  encodeURIComponent(newer.slug) +
                  '"><span class="micro">← NEWER ENTRY</span><strong>' +
                  MD.escapeHtml(newer.title) +
                  "</strong></a>"
                : "<div></div>") +
              (older
                ? '<a class="writing-adj-card writing-adj-next" href="writing.html?slug=' +
                  encodeURIComponent(older.slug) +
                  '"><span class="micro">OLDER ENTRY →</span><strong>' +
                  MD.escapeHtml(older.title) +
                  "</strong></a>"
                : "<div></div>");
            prevNextEl.classList.remove("hidden");
          }
        }
      }
    });
  }
})();
