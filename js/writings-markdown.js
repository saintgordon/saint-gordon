/* Saint Gordon Collective — Safe Markdown & Rich Media Renderer (Zero Dependencies) */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.SaintWritingsMarkdown = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function escapeHtml(str) {
    return String(str == null ? "" : str).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function sanitizeUrl(raw) {
    const val = String(raw || "").trim();
    if (!val) return "";
    if (/^(writings\/media\/|assets\/|\/api\/writings\?action=media&file=)[a-zA-Z0-9._/%?=&-]+$/.test(val)) {
      return val;
    }
    try {
      const u = new URL(val);
      if (u.protocol === "https:" || u.protocol === "http:") {
        return u.href;
      }
    } catch (_) {
      return "";
    }
    return "";
  }

  function resolveMediaSrc(rawSrc) {
    const safe = sanitizeUrl(rawSrc);
    if (!safe) return { primary: "", fallback: "" };
    const mediaMatch = safe.match(/^writings\/media\/([a-zA-Z0-9._-]+)$/);
    if (mediaMatch) {
      const file = encodeURIComponent(mediaMatch[1]);
      return {
        primary: safe,
        fallback: "/api/writings?action=media&file=" + file,
      };
    }
    return { primary: safe, fallback: "" };
  }

  function parseEmbedUrl(rawUrl) {
    const safe = sanitizeUrl(rawUrl);
    if (!safe) return null;

    // Direct video file
    if (/\.(mp4|webm|mov)(\?.*)?$/i.test(safe) || /action=media&file=[^&]+\.(mp4|webm|mov)$/i.test(safe)) {
      const media = resolveMediaSrc(safe);
      return { type: "video", src: media.primary, fallback: media.fallback };
    }

    // Direct audio file
    if (/\.(mp3|wav|ogg|m4a)(\?.*)?$/i.test(safe) || /action=media&file=[^&]+\.(mp3|wav)$/i.test(safe)) {
      const media = resolveMediaSrc(safe);
      return { type: "audio", src: media.primary, fallback: media.fallback };
    }

    try {
      const u = new URL(safe);
      const host = u.hostname.replace(/^www\./, "").toLowerCase();

      // YouTube (watch, shorts, embed, youtu.be)
      let ytId = "";
      if (host === "youtu.be") {
        ytId = u.pathname.replace(/^\//, "").split("/")[0];
      } else if (host === "youtube.com" || host === "m.youtube.com" || host === "youtube-nocookie.com") {
        if (u.pathname === "/watch") {
          ytId = u.searchParams.get("v") || "";
        } else if (u.pathname.startsWith("/shorts/") || u.pathname.startsWith("/embed/")) {
          ytId = u.pathname.split("/")[2] || "";
        }
      }
      if (ytId && /^[a-zA-Z0-9_-]{6,16}$/.test(ytId)) {
        return {
          type: "youtube",
          embedUrl: "https://www.youtube-nocookie.com/embed/" + encodeURIComponent(ytId) + "?rel=0",
          label: "YouTube video",
        };
      }

      // Vimeo
      if (host === "vimeo.com" || host === "player.vimeo.com") {
        const vm = u.pathname.match(/\/(?:video\/)?(\d{5,14})/);
        if (vm) {
          return {
            type: "vimeo",
            embedUrl: "https://player.vimeo.com/video/" + vm[1],
            label: "Vimeo video",
          };
        }
      }

      // SoundCloud
      if (host === "soundcloud.com" || host === "m.soundcloud.com") {
        const cleanSc = "https://soundcloud.com" + u.pathname;
        return {
          type: "soundcloud",
          embedUrl:
            "https://w.soundcloud.com/player/?url=" +
            encodeURIComponent(cleanSc) +
            "&color=%23101010&auto_play=false&hide_related=true&show_comments=false&show_user=true&show_reposts=false&show_teaser=false",
          label: "SoundCloud player",
        };
      }
    } catch (_) {
      return null;
    }

    return null;
  }

  function renderEmbedHtml(embed, caption) {
    const capHtml = caption ? '<figcaption class="writing-caption micro">' + escapeHtml(caption) + "</figcaption>" : "";
    if (embed.type === "youtube" || embed.type === "vimeo") {
      return (
        '<figure class="writing-figure writing-video-wrap">' +
        '<div class="writing-embed-16x9">' +
        '<iframe src="' +
        escapeHtml(embed.embedUrl) +
        '" title="' +
        escapeHtml(caption || embed.label) +
        '" loading="lazy" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; fullscreen" allowfullscreen></iframe>' +
        "</div>" +
        capHtml +
        "</figure>"
      );
    }
    if (embed.type === "soundcloud") {
      return (
        '<figure class="writing-figure writing-audio-embed">' +
        '<iframe class="writing-sc-frame" src="' +
        escapeHtml(embed.embedUrl) +
        '" title="' +
        escapeHtml(caption || "SoundCloud track") +
        '" loading="lazy" allow="autoplay"></iframe>' +
        capHtml +
        "</figure>"
      );
    }
    if (embed.type === "video") {
      const fallbackSrc = embed.fallback ? '<source src="' + escapeHtml(embed.fallback) + '" />' : "";
      return (
        '<figure class="writing-figure writing-video-wrap">' +
        '<video class="writing-video" controls playsinline preload="metadata">' +
        '<source src="' +
        escapeHtml(embed.src) +
        '" />' +
        fallbackSrc +
        "</video>" +
        capHtml +
        "</figure>"
      );
    }
    if (embed.type === "audio") {
      const fallbackSrc = embed.fallback ? '<source src="' + escapeHtml(embed.fallback) + '" />' : "";
      return (
        '<figure class="writing-figure writing-audio-wrap">' +
        '<audio class="writing-audio" controls preload="metadata">' +
        '<source src="' +
        escapeHtml(embed.src) +
        '" />' +
        fallbackSrc +
        "</audio>" +
        capHtml +
        "</figure>"
      );
    }
    return "";
  }

  function renderImageHtml(altText, rawSrc) {
    const embed = parseEmbedUrl(rawSrc);
    if (embed && (embed.type === "video" || embed.type === "audio" || embed.type === "youtube" || embed.type === "vimeo" || embed.type === "soundcloud")) {
      return renderEmbedHtml(embed, altText);
    }
    const media = resolveMediaSrc(rawSrc);
    if (!media.primary) return "";
    const fbAttr = media.fallback ? ' data-fallback-src="' + escapeHtml(media.fallback) + '"' : "";
    const capHtml = altText ? '<figcaption class="writing-caption micro">' + escapeHtml(altText) + "</figcaption>" : "";
    return (
      '<figure class="writing-figure">' +
      '<img src="' +
      escapeHtml(media.primary) +
      '" alt="' +
      escapeHtml(altText || "Post media") +
      '" loading="lazy"' +
      fbAttr +
      " />" +
      capHtml +
      "</figure>"
    );
  }

  function renderInline(text) {
    const tokens = [];
    const stash = function (html) {
      const id = "\x00TOK" + tokens.length + "\x00";
      tokens.push(html);
      return id;
    };

    let s = String(text || "");

    // Inline code first so markdown inside backticks is untouched
    s = s.replace(/`([^`\n]+)`/g, function (_, code) {
      return stash("<code>" + escapeHtml(code) + "</code>");
    });

    // Inline images ![alt](url)
    s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, function (_, alt, url) {
      const media = resolveMediaSrc(url);
      if (!media.primary) return escapeHtml(alt);
      const fbAttr = media.fallback ? ' data-fallback-src="' + escapeHtml(media.fallback) + '"' : "";
      return stash(
        '<img class="writing-inline-img" src="' +
          escapeHtml(media.primary) +
          '" alt="' +
          escapeHtml(alt || "Image") +
          '" loading="lazy"' +
          fbAttr +
          " />"
      );
    });

    // Links [label](url)
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (_, label, url) {
      const safe = sanitizeUrl(url);
      if (!safe) return escapeHtml(label);
      const isExt = /^https?:\/\//i.test(safe);
      const extAttrs = isExt ? ' target="_blank" rel="noopener noreferrer"' : "";
      return stash('<a href="' + escapeHtml(safe) + '"' + extAttrs + ">" + escapeHtml(label) + "</a>");
    });

    s = escapeHtml(s);

    // Bold, Italic, Strikethrough
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/__([^_]+)__/g, "<strong>$1</strong>");
    s = s.replace(/~~([^~]+)~~/g, "<del>$1</del>");
    s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    s = s.replace(/(^|[^_])_([^_\n]+)_/g, "$1<em>$2</em>");

    // Restore stashed HTML
    s = s.replace(/\x00TOK(\d+)\x00/g, function (_, idx) {
      return tokens[Number(idx)] || "";
    });

    return s;
  }

  function renderMarkdown(markdown) {
    const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!trimmed) {
        i++;
        continue;
      }

      // Fenced code block ```
      if (trimmed.startsWith("```")) {
        const lang = trimmed.slice(3).trim();
        const codeLines = [];
        i++;
        while (i < lines.length && !lines[i].trim().startsWith("```")) {
          codeLines.push(lines[i]);
          i++;
        }
        if (i < lines.length) i++;
        const langAttr = lang ? ' data-lang="' + escapeHtml(lang) + '"' : "";
        out.push('<pre class="writing-pre"' + langAttr + "><code>" + escapeHtml(codeLines.join("\n")) + "</code></pre>");
        continue;
      }

      // Horizontal rule
      if (/^(?:---+|\*\*\*+|___+)$/.test(trimmed)) {
        out.push('<hr class="writing-hr" />');
        i++;
        continue;
      }

      // Headings (# through ####)
      const hMatch = trimmed.match(/^(#{1,4})\s+(.+)$/);
      if (hMatch) {
        const level = Math.min(4, Math.max(2, hMatch[1].length));
        out.push("<h" + level + ">" + renderInline(hMatch[2].trim()) + "</h" + level + ">");
        i++;
        continue;
      }

      // Standalone image or media line ![caption](url)
      const imgMatch = trimmed.match(/^!\[([^\]]*)\]\(([^)\s]+)\)$/);
      if (imgMatch) {
        const html = renderImageHtml(imgMatch[1], imgMatch[2]);
        if (html) out.push(html);
        i++;
        continue;
      }

      // Standalone video/audio embed URL (YouTube, Vimeo, SoundCloud, MP4, WebM, MP3, WAV)
      if (/^https?:\/\/\S+$/.test(trimmed) || /^writings\/media\/\S+$/.test(trimmed)) {
        const embed = parseEmbedUrl(trimmed);
        if (embed) {
          out.push(renderEmbedHtml(embed, ""));
          i++;
          continue;
        }
      }

      // Blockquote
      if (trimmed.startsWith(">")) {
        const quoteLines = [];
        while (i < lines.length && lines[i].trim().startsWith(">")) {
          quoteLines.push(lines[i].trim().replace(/^>\s?/, ""));
          i++;
        }
        out.push("<blockquote><p>" + quoteLines.map(renderInline).join("<br />") + "</p></blockquote>");
        continue;
      }

      // Unordered list
      if (/^[-*+]\s+/.test(trimmed)) {
        const items = [];
        while (i < lines.length && /^[-*+]\s+/.test(lines[i].trim())) {
          items.push("<li>" + renderInline(lines[i].trim().replace(/^[-*+]\s+/, "")) + "</li>");
          i++;
        }
        out.push("<ul>" + items.join("") + "</ul>");
        continue;
      }

      // Ordered list
      if (/^\d+\.\s+/.test(trimmed)) {
        const items = [];
        while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
          items.push("<li>" + renderInline(lines[i].trim().replace(/^\d+\.\s+/, "")) + "</li>");
          i++;
        }
        out.push("<ol>" + items.join("") + "</ol>");
        continue;
      }

      // Paragraph (accumulate until blank line or block opener)
      const paraLines = [];
      while (i < lines.length) {
        const cur = lines[i].trim();
        if (
          !cur ||
          cur.startsWith("```") ||
          /^(?:---+|\*\*\*+|___+)$/.test(cur) ||
          /^#{1,4}\s+/.test(cur) ||
          cur.startsWith(">") ||
          /^[-*+]\s+/.test(cur) ||
          /^\d+\.\s+/.test(cur) ||
          /^!\[([^\]]*)\]\(([^)\s]+)\)$/.test(cur)
        ) {
          break;
        }
        paraLines.push(renderInline(cur));
        i++;
      }
      if (paraLines.length) {
        out.push("<p>" + paraLines.join("<br />") + "</p>");
      }
    }

    return out.join("\n");
  }

  function stripMarkdown(md) {
    return String(md || "")
      .replace(/```[\s\S]*?```/g, " ")
      .replace(/`([^`]+)`/g, "$1")
      .replace(/!\[([^\]]*)\]\([^)]+\)/g, " $1 ")
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
      .replace(/https?:\/\/\S+/g, " ")
      .replace(/[#>*_~\-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function slugify(str) {
    return String(str || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/-{2,}/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 80);
  }

  function estimateReadingTime(md) {
    const words = stripMarkdown(md).split(/\s+/).filter(Boolean).length;
    return Math.max(1, Math.round(words / 210));
  }

  function formatDisplayDate(dateStr) {
    if (!dateStr) return "";
    const parts = String(dateStr).slice(0, 10).split("-").map(Number);
    if (parts.length !== 3 || parts.some(isNaN)) return String(dateStr);
    const dt = new Date(Date.UTC(parts[0], parts[1] - 1, parts[2]));
    return dt.toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      timeZone: "UTC",
    });
  }

  function attachMediaFallbacks(container) {
    if (!container) return;
    container.querySelectorAll("img[data-fallback-src]").forEach(function (img) {
      img.addEventListener("error", function onErr() {
        const fb = img.getAttribute("data-fallback-src");
        if (fb && img.getAttribute("src") !== fb) {
          img.removeAttribute("data-fallback-src");
          img.setAttribute("src", fb);
        }
      });
    });
  }

  return {
    escapeHtml: escapeHtml,
    sanitizeUrl: sanitizeUrl,
    resolveMediaSrc: resolveMediaSrc,
    parseEmbedUrl: parseEmbedUrl,
    renderMarkdown: renderMarkdown,
    stripMarkdown: stripMarkdown,
    slugify: slugify,
    estimateReadingTime: estimateReadingTime,
    formatDisplayDate: formatDisplayDate,
    attachMediaFallbacks: attachMediaFallbacks,
  };
});
