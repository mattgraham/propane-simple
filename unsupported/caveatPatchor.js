/* MD5 LIB */
/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Copyright (C) Paul Johnston 1999 - 2000.
 * Updated by Greg Holt 2000 - 2001.
 * See http://pajhome.org.uk/site/legal.html for details.
 */

/*
 * Convert a 32-bit number to a hex string with ls-byte first
 */
var hex_chr = "0123456789abcdef";
function rhex(num)
{
  str = "";
  for(j = 0; j <= 3; j++)
    str += hex_chr.charAt((num >> (j * 8 + 4)) & 0x0F) +
           hex_chr.charAt((num >> (j * 8)) & 0x0F);
  return str;
}

/*
 * Convert a string to a sequence of 16-word blocks, stored as an array.
 * Append padding bits and the length, as described in the MD5 standard.
 */
function str2blks_MD5(str)
{
  nblk = ((str.length + 8) >> 6) + 1;
  blks = new Array(nblk * 16);
  for(i = 0; i < nblk * 16; i++) blks[i] = 0;
  for(i = 0; i < str.length; i++)
    blks[i >> 2] |= str.charCodeAt(i) << ((i % 4) * 8);
  blks[i >> 2] |= 0x80 << ((i % 4) * 8);
  blks[nblk * 16 - 2] = str.length * 8;
  return blks;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * These functions implement the basic operation for each round of the
 * algorithm.
 */
function cmn(q, a, b, x, s, t)
{
  return add(rol(add(add(a, q), add(x, t)), s), b);
}
function ff(a, b, c, d, x, s, t)
{
  return cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function gg(a, b, c, d, x, s, t)
{
  return cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function hh(a, b, c, d, x, s, t)
{
  return cmn(b ^ c ^ d, a, b, x, s, t);
}
function ii(a, b, c, d, x, s, t)
{
  return cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Take a string and return the hex representation of its MD5.
 */
function calcMD5(str)
{
  x = str2blks_MD5(str);
  a =  1732584193;
  b = -271733879;
  c = -1732584194;
  d =  271733878;

  for(i = 0; i < x.length; i += 16)
  {
    olda = a;
    oldb = b;
    oldc = c;
    oldd = d;

    a = ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = ff(c, d, a, b, x[i+10], 17, -42063);
    b = ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = ff(d, a, b, c, x[i+13], 12, -40341101);
    c = ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = gg(c, d, a, b, x[i+11], 14,  643717713);
    b = gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = gg(c, d, a, b, x[i+15], 14, -660478335);
    b = gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = hh(b, c, d, a, x[i+14], 23, -35309556);
    a = hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = hh(d, a, b, c, x[i+12], 11, -421815835);
    c = hh(c, d, a, b, x[i+15], 16,  530742520);
    b = hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = ii(c, d, a, b, x[i+10], 15, -1051523);
    b = ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = ii(d, a, b, c, x[i+15], 10, -30611744);
    c = ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = add(a, olda);
    b = add(b, oldb);
    c = add(c, oldc);
    d = add(d, oldd);
  }
  return rhex(a) + rhex(b) + rhex(c) + rhex(d);
}
/* END MD5 LIB */

// Why isn't this part of JS? Bunk.
// Yes, this is clever. /deal with it
function xor(a,b)
{
  return !a != !b
}

var displayAvatars = true;

if (displayAvatars) {

  var USER_ACTIONS = ['enter','leave','kick','conference_created','lock','unlock','topic_change','allow_guests','disallow_guests'];

  Object.extend(Campfire.Message.prototype, {
    authorID: function() {
      if (Element.hasClassName(this.element, 'you'))
        return this.chat.userID;

      var idtext = (this.element.className.match(/\s*user_(\d+)\s*/) || [])[1];
      return parseInt(idtext) || 0;
    },

    addAvatar: function() {
      var
        author = this.authorElement(),
        body = this.bodyCell,
        email,
        avatar, name, imgSize = 32, img;

      email = author.getAttribute('data-email')
      if (email) {
        var hash = calcMD5(email.trim().toLowerCase())
        avatar = "http://gravatar.com/avatar/"+hash
      } else {
        // avatar = author.getAttribute('data-avatar') || 'http://asset1.37img.com/global/missing/avatar.png?r=3';
        avatar = 'http://globase.heroku.com/redirect/gh.gravatars.' + this.authorID() + '?default=http://github.com/images/gravatars/gravatar-140.png';
      }
      name = '<strong class="authorName" style="color:#333;">'+author.textContent+'</strong>'

      if (USER_ACTIONS.include(this.kind)) {
        imgSize = 16
        if ('conference_created' != this.kind)
          body = body.select('div:first')[0]
        name += ' '
      } else if (this.actsLikeTextMessage()) {
        name += '<br>'
      } else {
        return;
      }

      var aussie = AUSSIES.include(this.chat.username)
      var aussie_msg = AUSSIES.include(this.author())
      if(xor(aussie, aussie_msg)) {
        flip = "-webkit-transform: scaleY(-1);"
      } else {
        flip = ""
      }

      img = '<img alt="'+this.author()+'" "title="'+this.author()+'" width="'+imgSize+'" height="'+imgSize+'" align="absmiddle" style="opacity: 1.0; margin: 0px; border-radius:3px;'+flip+'" src="'+avatar+'">'

      if ('hubot' === author.textContent.toLowerCase()) {
        img = '<a target="_blank" href="https://team.githubapp.com/hubot" style="text-decoration:none important!; margin:0px; padding:0px; border-width:0px; ">'+img+'</a>'
      } else {
        img = '<a target="_blank" href="https://team.githubapp.com/hubbers/find_by_campfire?campfire_id='+this.authorID()+'" style="text-decoration:none important!; margin:0px; padding:0px; border-width:0px; ">'+img+'</a>'
      }

      if (USER_ACTIONS.include(this.kind)) {
        name = img + '&nbsp;&nbsp;' + name;
        img = ''
      }

      if (author.visible()) {
        author.hide();

        if (body.select('strong.authorName').length === 0) {
          body.insert({top: name});
          if (img)
            author.insert({after: img});
        }
      }
    }
  });

  /* if you can wrap rather than rewrite, use swizzle like this: */
  swizzle(Campfire.Message, {
    setAuthorVisibilityInRelationTo: function($super, message) {
      $super(message);
      this.addAvatar();
    },
    authorElement: function($super) {
      if (USER_ACTIONS.include(this.kind)) {
        return $super().select('span.author')[0]
      } else {
        return $super()
      }
    }
  });


  /* defining a new responder is probably the best way to insulate your hacks from Campfire and Propane */
  Campfire.AvatarMangler = Class.create({
    initialize: function(chat) {
      this.chat = chat;

      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        var message = messages[i];
        message.addAvatar();
      }

      this.chat.layoutmanager.layout();
      this.chat.windowmanager.scrollToBottom();
    },

    onMessagesInserted: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();

      for (var i = 0; i < messages.length; i++) {
        var message = messages[i];
        message.addAvatar();
      }

      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    }
  });

  /* Here is how to install your responder into the running chat */
  Campfire.Responders.push("AvatarMangler");
  window.chat.installPropaneResponder("AvatarMangler", "avatarmangler");
}

if (true) {
  Campfire.MeatbagExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectMeatbags(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectMeatbags: function(message) {
      /* we are going to use the messageID to uniquely identify our requestJSON request
         so we don't check pending messages */
      if (!message.pending() && message.kind === 'text') {
        var text = message.bodyElement().innerHTML;
        if (text.match(/^\w+ meatbags/)) {
          var names = text.match(/meatbags: (.+)$/)[1].split(', ')
          var pics = []

          for (var i=0; i < names.length; i++) {
            var name = names[i];
            name = name.replace(/\s+/g,'').toLowerCase()
            avatar = 'http://globase.heroku.com/redirect/gh.gravatars.' + name + '?default=http://github.com/images/gravatars/gravatar-140.png';
            pics.push('<img title="'+name+'" alt="'+name+'" width="32" height="32" align="middle" style="margin-right: 1px; opacity: 1.0; border-radius:3px; margin-bottom: 1px" src="'+avatar+'">')
          }

          message.bodyElement().update("" + pics.join(''))
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectMeatbags(messages[i]);
      }
      if ((this.chat.windowmanager.getScrollOffset() + this.chat.windowmanager.getWindowHeight()) >=
          (this.chat.windowmanager.getPageHeight() - 400)) {
          setTimeout(
          (function(cfobj) {
              return function() {
                  cfobj.chat.windowmanager.scrollToBottom();
              }
          })(this), 500);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    }
  });

  Campfire.Responders.push("MeatbagExpander");
  window.chat.installPropaneResponder("MeatbagExpander", "meatbagexpander");
}

if (true) {
  Campfire.GitHubExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectGitHubURL(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectGitHubURL: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var iframe = null, elem, height = 150;

        var gists = message.bodyElement().select('a[href*="gist.github.com"]');
        if (gists.length == 1) {
          elem = gists[0];
          var href = elem.getAttribute('href');
          var match = href.match(/^https?:\/\/gist.github.com\/([A-Fa-f0-9]+)/);
          if (match) {
            iframe = 'https://gist.github.com/'+match[1]+'.pibb';
          }
        }

        var blobs = message.bodyElement().select('a[href*="#L"]');
        if (blobs.length == 1) {
          elem = blobs[0];
          var href = elem.getAttribute('href');
          iframe = href;
        }

        var blobs = message.bodyElement().select('a[href*="/blob/"]');
        if (!iframe && blobs.length == 1 && message.author() != 'Hubot') {
          elem = blobs[0];
          var href = elem.getAttribute('href');
          if (href.indexOf('#') > -1)
            iframe = href;
          else
            iframe = href + '#L1';
        }

        var commits = message.bodyElement().select('a[href*="/commit/"]')
        if (!iframe && commits.length == 1 && message.author() != 'Hubot' && message.author() != 'Git') {
          elem = commits[0];
          var href = elem.getAttribute('href');
          if (href.indexOf('#') > -1)
            iframe = href;
          else
            iframe = href + '#diff-stat';
        }

        if (!iframe || IFRAME_HATERS.concat(HATERS).include(this.chat.username) || iframe.match(/Image-Diff-View-Modes/)) return;
        message.bodyElement().insert({bottom:"<iframe style='border:0; margin-top: 5px' height='"+height+"' width='98%' src='"+iframe+"'></iframe>"});
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectGitHubURL(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectGitHubURL(message);
    }
  });

  Campfire.Responders.push("GitHubExpander");
  window.chat.installPropaneResponder("GitHubExpander", "githubexpander");
}

if (true) {
  Campfire.CommitExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectCommit(messages[i]);
      }
    },

    detectCommit: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var body = message.bodyElement()
        if (body.innerText.match(/^\w+'s deploy of (.*) failed$|^Failed \w+ deploy/)) {
          message.bodyCell.setStyle({
            color: '#d55555'
          })
        }

        if (body.innerText.match(/is deploying/)) {
          var m = body.innerText.match(/^(.*?)(, logs| \(http:)/i)
          var links = body.select('a')
          if (links.length && m) {
            var last_link = links[links.length-1]
            var message = (links.length == 2) ? m[1].replace(/\((.*?)\)/, function(all,match){ return "(<a target='_blank' href='"+links[0].href+"'>" + match + "</a>)" }) : m[1]

            if (last_link.href.match(/heaven/)) {
              var build_num = last_link.href.match(/(\d+)$/)[1]
              message += ' [<b><a target="_blank" href="' + last_link.href + '">#' + build_num + '</a></b>]'
            }

            body.innerHTML = message
          }
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectCommit(messages[i]);
      }
    }
  });

  Campfire.Responders.push("CommitExpander");
  window.chat.installPropaneResponder("CommitExpander", "commitexpander");
}

if (true) {
  Campfire.GitHubURLShortener = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectGitHubURL(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectGitHubURL: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var authority = "//github.com/";
        var shortRef = function(str) { return /[^0-9a-f]/.test(str) ? str : str.substr(0, 7); }

        message.bodyElement().select('a[href*="' + authority + '"]').filter(function(link) {
          // We only want to modify links where the link's text is the URL.

          var text = link.innerText;
          if (text[text.length - 1] === "…") {
            // The URL has been truncated, so use a more lenient test.
            text = text.substr(0, text.length - 1);
            return link.href.indexOf(text) === 0;
          }
          return text == link.href;
        }).forEach(function(link) {
          var pathQueryFragment = decodeURIComponent(link.href.substr(link.href.indexOf(authority) + authority.length));

          var index = pathQueryFragment.indexOf("?");
          if (index < 0)
            index = pathQueryFragment.indexOf("#");
          if (index >= 0) {
            var path = pathQueryFragment.slice(0, index);
            var queryFragment = pathQueryFragment.slice(index);
          } else {
            var path = pathQueryFragment;
            var queryFragment = "";
          }

          var components = path.split("/");

          // Don't shorten blog links; they look silly.
          if (components[0] === "blog")
            return;

          var userRepo = components.splice(0, 2).join("/");

          if (components.length === 0) {
            // This is just a link to a repository.
            link.innerText = userRepo + queryFragment;
            return;
          }

          var command = components.splice(0, 1);

          var transformations = {
            blob: {
              regex: /([^\/]+)\/(.*)/,
              text: function(match) {
                return userRepo + "@" + shortRef(match[1]) + ":" + match[2];
              },
            },
            commit: {
              regex: /[0-9a-fA-F]+/,
              text: function(match) {
                return userRepo + "@" + shortRef(match[0]);
              },
            },
            issues: {
              regex: /\d+/,
              text: function(match) {
                return userRepo + "#" + match[0];
              },
            },
            pull: {
              regex: /\d+/,
              text: function(match) {
                return userRepo + "#" + match[0];
              },
            },
            compare: {
              regex: /(.*?)\.\.\.(.*)/,
              text: function(match) {
                return userRepo + "@" + shortRef(match[1]) + "..." + shortRef(match[2]);
              },
            },
          };

          if (!(command in transformations))
            return;
          transformation = transformations[command];
          var match = components.join("/").match(transformation.regex);
          if (!match)
            return;
          link.innerText = transformation.text(match) + queryFragment;
        });
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectGitHubURL(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectGitHubURL(message);
    }
  });

  Campfire.Responders.push("GitHubURLShortener");
  window.chat.installPropaneResponder("GitHubURLShortener", "githuburlshortener");
}

if (true) {
  Campfire.BuildExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectBuild(messages[i]);
      }
    },

    detectBuild: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var body = message.bodyElement()
        if (body.innerText.match(/^Build #(\d+) \([0-9a-zA-Z]+\) of (github-)?([-_0-9a-zA-Z]+)/)) {
          var failed_p = body.innerText.match(/failed/);
          var success_p = body.innerText.match(/success/);
          var color = failed_p ? '#d55555' : '#58C04F';
          if (failed_p || success_p)
            message.bodyCell.setStyle({
              color: color
            })

          var sha = body.innerText.match(/\(([0-9a-z]+)\)/i)[1]
          var build;
          if (body.outerHTML.match(/^github-(?!services)/)) {
           build = body.outerHTML.replace(/#(\d+) \(([0-9a-zA-Z]+)\) of (?:github-)?([-_0-9a-zA-Z]+)/, '<a target="_blank" href="http://ci2.rs.github.com:8080/job/github-$3/$1/console">#$1</a> ($2) of github-$3')
          } else {
            build = body.outerHTML.replace(/#(\d+) \(([0-9a-zA-Z]+)\) of ([-_0-9a-zA-Z]+)/, '<a target="_blank" href="https://janky.rs.github.com/$1/output">#$1</a> ($2) of $3')
          }
          var btime = build.match(/\d+s/)
          body.replace(build)
          build = build.replace(/^.*?<a/,'<a').replace(/<\/a>.*/, '</a>')

          var msgIndex = this.chat.transcript.messages.indexOf(message);
          if (msgIndex > -1) {
            for (var i=msgIndex; i > 0 && i > msgIndex - 5; i--) {
              var otherMsg = this.chat.transcript.messages[i]
              if (otherMsg.element.innerHTML.match("/commit/" + sha)) {
                build = build.replace(/<\/a>.*$/, '</a>').replace('Build ','');
                if (btime) build += "] [" + btime;
                otherMsg.bodyElement().insert({bottom: " ["+build+"]"})
                otherMsg.bodyCell.setStyle({color:color})
                message.element.remove()
                break
              }
            }
          }
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectBuild(messages[i]);
      }
    }
  });

  Campfire.Responders.push("BuildExpander");
  window.chat.installPropaneResponder("BuildExpander", "buildexpander");
}

if (true) {
  Campfire.GFMExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectGFM(messages[i]);
      }
    },

    detectGFM: function(message) {
      if (message.kind === 'text') {
        var body = message.bodyElement()
        var text = body.innerText
        var regex = /(\s|^)([\w-]+\/[\w-]+)(@|#)([a-f0-9]+|\d+)\b/g

        if (text.match(regex)) {
          var html = body.innerHTML
          html = html.replace(regex, function(all, space, nwo, type, num){
            var link;
            if (type == '@') {
              link = "https://github.com/" + nwo + "/commit/" + num
            } else {
              link = "https://github.com/" + nwo + "/issues/" + num
            }

            return space + "<a target='_blank' href='"+link+"'>" + nwo + type + num + "</a>"
          })
          body.innerHTML = html
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectGFM(messages[i]);
      }
    }
  });

  Campfire.Responders.push("GFMExpander");
  window.chat.installPropaneResponder("GFMExpander", "gfmexpander");
}

if (true) {
  Campfire.GraphExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectGraph(messages[i]);
      }
    },

    detectGraph: function(message) {
      var body = message.bodyElement()
      var imgs = body.select('a img[src*="graph.png"]')
      if (imgs.length) {
        for (var i=0; i<imgs.length; i++) {
          var img = imgs[i]
          var src = img.src
          var opts = src.match(/\?(.+?)(#\.png)$/)

          img.setStyle({'max-width':'1024px', 'max-height':'70%'})
          if (opts) {
            var graphme = 'http://graphme.herokuapp.com/editor.html?'+opts[1]
            img.up('a').href = graphme
            // img.onclick = function(){
            //   window.open(graphme, '_newtab')
            //   return false
            // }
          }
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectGraph(messages[i]);
      }
    }
  });

  Campfire.Responders.push("GraphExpander");
  window.chat.installPropaneResponder("GraphExpander", "graphexpander");
}

if (true) {
  Campfire.StacheExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectStache(messages[i]);
      }
    },

    detectStache: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var body = message.bodyElement()
        var imgs = body.select('a.image[href*="faceup.me"]')
        if (imgs.length) {
          var src = decodeURIComponent(imgs[0].href.replace(/^.*\?overlay=.*&src=/,''))

          var msgIndex = this.chat.transcript.messages.indexOf(message);
          if (msgIndex > -1) {
            for (var i=msgIndex-1; i > 0 && i > msgIndex - 7; i--) {
              var otherMsg = this.chat.transcript.messages[i]
              var found = otherMsg.bodyElement().select('a.image')
              if (found.length) {
                var h = found[0].href.replace(/#\....$/,'')
                if (h == src || decodeURIComponent(h) == src) {
                  otherMsg.bodyElement().select('a.image')[0].setStyle({'padding-right': '5px'})
                  otherMsg.bodyElement().insert({bottom: imgs[0]})
                  message.element.remove()
                  break
                }
              }
            }
          }

        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectStache(messages[i]);
      }
    }
  });

  Campfire.Responders.push("StacheExpander");
  window.chat.installPropaneResponder("StacheExpander", "stacheexpander");
}

if (true) {
  Campfire.DiffExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectDiff(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectDiff: function(message) {
      if (message.kind === 'paste') {
        var pre = message.bodyCell.select('pre')
        var code = message.bodyCell.select('pre code')
        if (code.length) {
          /* nowrap hax */
          pre[0].setStyle({'word-wrap':'normal','white-space':'pre'})
          code[0].setStyle({'overflow-x':'scroll'})

          var diff = code[0].innerText
          if (diff.match(/^\+\+\+/m)) {
            var lines = diff.split("\n").map(function(line){
              if (line.match(/^(diff|index)/)) {
                return "<b>"+line.escapeHTML()+"</b>"
              } else if (match = line.match(/^(@@.+?@@)(.*)$/)) {
                return "<b>"+match[1]+"</b> " + match[2].escapeHTML()
              } else if (line.match(/^\+/)) {
                return "<font style='color:green'>"+line.escapeHTML()+"</font>"
              } else if (line.match(/^\-/)) {
                return "<font style='color:red'>"+line.escapeHTML()+"</font>"
              } else {
                return line.escapeHTML()
              }
            })
            code[0].innerHTML = lines.join("\n")
          }
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectDiff(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectDiff(message);
    }
  });

  Campfire.Responders.push("DiffExpander");
  window.chat.installPropaneResponder("DiffExpander", "diffexpander");
}

if (true) {
  Campfire.HTMLExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectHTML(messages[i], true);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectHTML: function(message, noplay) {
      if (!message.pending() && ['text','paste'].include(message.kind)) {
        var body = message.bodyElement()
        var orig = body.innerHTML
        var match = body.innerText.match(/^HTML!\s+(.+)$/m);

        //if (noplay && !body.innerText.match(/<audio/)) return;

        // Some people can't handle this much fun
        if ((noplay || SOUND_HATERS.concat(HATERS).include(this.chat.username)) && /<audio/.test(body.innerText)) {
          match[1] = match[1].replace('autoplay','')
        }

        if (match && !body.innerText.match(/<\s*script/i)) {
          // find and fix truncated links
          var links = {}
          orig.replace(/<a href="(.+?)" target="_blank">(.+?…)<\/a>/, function(all, href, text){ links[text]=href; return all })

          var html = match[1].replace(/(h.*?…)/, function(all, link){ return links[link] || link })
          body.update(html)
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectHTML(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectHTML(message);
    }
  });

  Campfire.Responders.push("HTMLExpander");
  window.chat.installPropaneResponder("HTMLExpander", "htmlexpander");
}

if (false) {
  swizzle(Campfire.StarManager, {
    toggle: function($super, element) {
      $super(element);

      var star = $(element).up('span.star'),
          message = this.chat.findMessage(element)
      if (star.hasClassName('starred')) {
        trackStar(message);
      }
    }
  });

  // 5490ef76-50fa-11e0-8fed-2495f6688d41
  // bb628a4e-5199-11e0-949d-2e03dd584bf3 is a test cluster
  function trackStar(message) {
    var id   = message.id()
      , url  = "http://allofthestars.com/clusters/5490ef76-50fa-11e0-8fed-2495f6688d41/campfire" +
        "?message="    + encodeURIComponent(message.bodyElement().innerText) +
        "&message_id=" + encodeURIComponent(id.toString()) +
        "&url="        + encodeURIComponent(starPermalink(id)) +
        "&author="     + encodeURIComponent(message.author()) +
        "&room="       + encodeURIComponent($('room_name').innerText)
    if (window.propane) window.propane.requestJSON(id, url)
  }

  function starPermalink(id) {
    return location.href.toString().replace(/#.*/, '') +
      "transcript/message/" + id + "#message_" + id
  }
}

if (true) {
    Campfire.TheRedactor = Class.create({
    initialize: function(chat) {
      this.room_name = $('room_name').innerText;
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.redactThatShit(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    repeat: function(str, n) {
      var result = ''
      for(i = 0; i < n; i++) {
        result += str
      }
      return result
    },
    redactWord: function(word) {
      return this.repeat('█', word.length)
    },

    ensureRedaction: function(message) {
      var parts = message.split(/(\s+)/)

      var nonwhitespace_indices = []
      for(var i = 0; i < parts.length; i++) {
        if(!parts[i].match(/\s/)) {
          nonwhitespace_indices = nonwhitespace_indices.concat(i)
        }
      }
      var x = nonwhitespace_indices[Math.floor(Math.random() * nonwhitespace_indices.length)]

      parts[x] = this.redactWord(parts[x])

      var ensured = parts.join('')
      return ensured
    },
    redactThatShit: function(message) {
      if (!message.pending() && ['text','paste'].include(message.kind)) {
        var body = message.bodyElement()
        var orig = body.innerHTML

        var ths = this  // total hack

        if (message.author() != 'Hubot' && this.room_name == 'The [Redacted] Room') {
          var ensured = this.ensureRedaction(orig)
          var updated = ensured.replace(/([\w'-]+)/g, function(all, word) {
            if (Math.random() < 0.6) {
              return ths.redactWord(word)
            } else {
              return word
            }
          })
          body.update(updated)
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.redactThatShit(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.redactThatShit(message);
    }
  });

  Campfire.Responders.push("TheRedactor");
  window.chat.installPropaneResponder("TheRedactor", "theredactor");
}

if (true) {
  // from github.com/about
  STAFF = 'tater,hubot,tpw,chris,pj,pjhyett,scott,tekkub,melissa,kyle,rtomayko,zach,technoweenie,atmos,tim,brianmario,petros,bryan,peff,cameron,probablycorey,tclem,sr,tmm1,josh,beth,kevin,alex,vicent,jp,ben,jason,benburkert,heather,kami,matt,maddox,paul,mattg,mccullough,aw,jesse,jina,justin,sonya,roberto,lee,jake,danny,russell,adam,jbarnette,kevinsawicki,bleikamp,julie,jnewland,danish,sean,kyros,newman,garrett,jakedouglas,huffman,jonrohan,twp,cameronmcefee,rodjek,phil,Haacked,rando,skalnik,cobyism,jakeboxer,jsncostello,Rob,paulbetts,tnm,julia,scottjg,keavy,dreww,danishkhan,billyroh,rick,ymendel,vinbarnes,shepbook,aspires,derekgr,razic,lukehefson,obfuscurity,half-ogre,nickh,jm,erebor,orderedlist,jonmagic,jnunemaker,bkeepers'
  ALIAS = {
    mtodd: 'matt',
    matttodd: 'matt',
    mattmatttoddtodd: 'matt',
    kneath: 'kyle',
    mojombo: 'tpw',
    defunkt: 'chris',
    aman: 'tmm1',
    beard: 'brianmario',
    pug: 'tater',
    holman: 'zach',
    ryan: 'rtomayko',
    tomayko: 'tomayko',
    tom: 'tpw',
    tanoku: 'vicent',
    sundaykofax: 'sonya',
    bryanveloso: 'bryan',
    newmerator: 'newman',
    bradley: 'rick',
    halfogre: 'half-ogre',
    nunemaker: 'jnunemaker',
    nunes: 'jnunemaker',
    rsanheim: 'rob'
  }
  GITHUB_STAFF = new RegExp(":(" + STAFF.split(",").join("|") + "):", 'ig')
  GITHUB_ALIAS = new RegExp(":(" + new Hash(ALIAS).keys().join("|") + "):", 'ig')


  CUSTOM_EMOJI = {
    wolverine : 'http://cl.ly/EDpr/out.gif',
    poke      : 'http://f.cl.ly/items/3q1B262I1h0p0v0v460F/poke.gif',
    beart     : 'http://f.cl.ly/items/1F0E1p2l0n0x0P2Z3T2q/beart.png'
  }
  CUSTOM_EMOJI_REGEX = new RegExp(":(" + new Hash(CUSTOM_EMOJI).keys().join("|") + "):", 'ig')

  Campfire.EmojiExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectEmoji(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectEmoji: function(message) {
      if (message.kind == 'text') {
        var body = message.bodyElement()
        var emoji = body.select('span.emoji');
        emoji.each(function(e){
          var name = e.className.match(/emoji-([^\s]+)/)[1]

          var size = 28
          if (name == 'octocat') size = 40
          if (message.author() == 'Hubot') size = 18

          e.replace( "<img title=':"+name+":' alt=':"+name+":' src='http://github.com/images/icons/emoji/"+name+".png' height='"+size+"' width='"+size+"' align='absmiddle'/>" )
        })

        var html = body.innerHTML
        var match = html.match(CUSTOM_EMOJI_REGEX)
        if (match && !EMOJI_HATERS.concat(HATERS).include(this.chat.username)) {
          body.innerHTML = html.replace(CUSTOM_EMOJI_REGEX, function(all, e){
            var size = 40
            var url = CUSTOM_EMOJI[e]
            if (message.author() == 'Hubot') size = 18
            return "<img title=':"+e+":' alt=':"+e+":' src='"+url+"' height='"+size+"' width='"+size+"' align='absmiddle' style='margin-right: 1px; margin-bottom: 1px; opacity: 1.0; border-radius:3px'/>"
          })
        }

        var html = body.innerHTML
        var match = html.match(GITHUB_STAFF)
        if (match) {
          body.innerHTML = html.replace(GITHUB_STAFF, function(all, e){
            var size = 28
            if (message.author() == 'Hubot') size = 18
            return "<img title=':"+e+":' alt=':"+e+":' src='http://globase.heroku.com/redirect/gh.gravatars."+e.toLowerCase()+"' height='"+size+"' width='"+size+"' align='absmiddle' style='margin-right: 1px; margin-bottom: 1px; opacity: 1.0; border-radius:3px'/>"
          })
        }

        var html = body.innerHTML
        var match = html.match(GITHUB_ALIAS)
        if (match) {
          body.innerHTML = html.replace(GITHUB_ALIAS, function(all, e){
            var size = 28
            var name = ALIAS[e]
            if (message.author() == 'Hubot') size = 18
            return "<img title=':"+e+":' alt=':"+e+":' src='http://globase.heroku.com/redirect/gh.gravatars."+name.toLowerCase()+"' height='"+size+"' width='"+size+"' align='absmiddle' style='margin-right: 1px; margin-bottom: 1px; opacity: 1.0; border-radius:3px'/>"
          })
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectEmoji(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectEmoji(message);
    }
  });

  Campfire.Responders.push("EmojiExpander");
  window.chat.installPropaneResponder("EmojiExpander", "emojiexpander");
}

if (true) {
  Campfire.MusicExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectMusic(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectMusic: function(message) {
      if (message.actsLikeTextMessage()) {
        var body = message.bodyElement()
        var html = body.innerHTML

        var match = html.match(/(Now playing|is listening to|Queued up) "(.*)" by (.*), from(?: the album)? "(.*)"(.*)/i)
        if (match) {
          var text = match[1]
          var song = match[2], artist = match[3], album = match[4], rest = match[5]
          var url = "http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Ddigital-music&x=8&y=16&field-keywords="
          var linkify = function(text, query){
            if (!query) query = text
            return new Element('a', {target:'_blank',href:url+encodeURI(query)}).update(text).outerHTML;
          }

          html = text + ' "'
          if (song)
            html += linkify(song, song+" "+artist+" "+album)
          html += '" by '
          if (artist)
            html += linkify(artist)
          html += ', from the album "'
          if (album)
            html += linkify(album, artist+" "+album)
          html += '"'
          html += rest
          body.innerHTML = html
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectMusic(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectMusic(message);
    }
  });

  Campfire.Responders.push("MusicExpander");
  window.chat.installPropaneResponder("MusicExpander", "musicexpander");
}

window.chat.messageHistory = 800;

/* focus/scroll hax */
// var $focused = true;
// window.onfocus = function(){ alert(1); $focused = true  }
// window.onblur  = function(){ $focused = false }
// swizzle(Campfire.WindowManager, {
//   isScrolledToBottom: function($super) {
//     return $focused ? $super() : false;
//   }
// });

/* begin infinite scroll */

/*
 * Simple JSONP utility with Prototype.js
 */
var JsonpRequest = Class.create({
    initialize: function(base_url, callback, options) {
    this.base_url = base_url;
    this.callback = callback;
    this.options = $H({
      callback_key: 'callback',
      param: { }
    });
    this.options.update(options);
    this.request();
  },

  request: function() {
    var handler_name = this.create_handler_name();
    var script_tag = new Element('script', {'type': 'text/javascript', 'src': this.url(handler_name)});

    var callback = this.callback;
    JsonpRequest[handler_name] = function(response) {
      script_tag.remove();
      delete JsonpRequest[handler_name];
      callback.call(this, response);
    };

    // alert(JSON.stringify(this.url(handler_name)))
    $$('head').first().insert(script_tag);
  },

  create_handler_name: function() {
    return 'handle_response_' + JsonpRequest.next_id++;
  },

  url: function(handler_name) {
    var param = $H(this.options.get('param'));
    param.set(this.options.get('callback_key'), 'JsonpRequest.' + handler_name);
    // alert(JSON.stringify(param))
    // alert(JSON.stringify(param.toQueryString()))
    param.update({
      return_to: window.location.href + '?backfill=1',
      '_': new Date().getTime()
    });
    return this.base_url + '?' + param.toQueryString()
  }
});
JsonpRequest.next_id = 0;


Campfire.Transcript.addMethods({
  /* maintainScrollPosition, html, *message_ids */
  prependMessages: function() {
    var ids = $A(arguments), maintainScrollPosition = ids.shift(), html = ids.shift();
    new Insertion.Top(this.element, html);
    this.findMessages()
    var messages = ids.map(this.getMessageById.bind(this));
    this.chat.dispatch('messagesInsertedBeforeDisplay', messages);
    messages.pluck('element').each(function(element) {
      Element.show(element);
      maintainScrollPosition();
    });
    this.chat.dispatch('messagesInserted', messages);
    return messages;
  }
})
Campfire.Transcript.messageTemplates = {
  text_message: new Template("<tr class=\"message text_message\" id=\"message_#{id}\"><td class=\"person\"><span class=\"author\" data-avatar=\"#{avatar}\" data-email=\"#{email_address}\" data-name=\"#{name}\">#{name}</span></td>\n  <td class=\"body\">\n    <div class=\"body\">#{body}</div>\n    \n  <span class=\"star \">\n    <a href=\"#\" onclick=\"chat.starmanager.toggle(this); return false;\" title=\"Starred lines appear as highlights in the transcript.\"></a>\n  </span>\n\n\n  </td>\n</tr>\n"),
  paste_message: new Template("<tr class=\"message paste_message\" id=\"message_#{id}\"><td class=\"person\"><span class=\"author\" data-avatar=\"#{avatar}\" data-email=\"#{email_address}\" data-name=\"#{name}\">#{name}</span></td>\n  <td class=\"body\">\n <a href=\"/room/#{room_id}/paste/#{id}\" target=\"_blank\">View paste</a> \n<br>   <div class=\"body\"><pre><code>#{body}</code></pre></div>\n    \n  <span class=\"star \">\n    <a href=\"#\" onclick=\"chat.starmanager.toggle(this); return false;\" title=\"Starred lines appear as highlights in the transcript.\"></a>\n  </span>\n\n\n  </td>\n</tr>\n"),
  tweet_message: new Template("<tr class=\"message tweet_message\" id=\"message_#{id}\"><td class=\"person\"><span class=\"author\" data-avatar=\"#{avatar}\" data-email=\"#{email_address}\" data-name=\"#{name}\">#{name}</span></td>\n  <td class=\"body\">\n <div class=\"body\"><span class=\"clearfix tweet\"><span class=\"tweet_avatar\"><a href=\"http://twitter.com/#{tweet.author_username}/status/#{tweet.id}\" target=\"_blank\"><img alt=\"Profile_normal\" height=\"48\" src=\"#{tweet.author_avatar_url}\" width=\"48\"></a></span> \n #{tweet.message} \n <span class=\"tweet_author\">— <a href=\"http://twitter.com/#{tweet.author_username}/status/#{tweet.id}\" class=\"tweet_url\" target=\"_blank\">@#{tweet.author_username}</a> via Twitter</span> </span></div>\n    \n  <span class=\"star \">\n    <a href=\"#\" onclick=\"chat.starmanager.toggle(this); return false;\" title=\"Starred lines appear as highlights in the transcript.\"></a>\n  </span>\n\n\n  </td>\n</tr>\n"),
  enter_message: new Template("<tr class=\"message enter_message\" id=\"message_#{id}\"><td class=\"person\"><span class=\"author\" data-avatar=\"#{avatar}\" data-email=\"#{email_address}\" data-name=\"#{name}\">#{name}</span></td>\n  <td class=\"body\">\n    <div>has entered the room</div>\n    \n\n\n  </td>\n</tr>\n"),
  kick_message: new Template("<tr class=\"message kick_message\" id=\"message_#{id}\"><td class=\"person\"><span class=\"author\" data-avatar=\"#{avatar}\" data-email=\"#{email_address}\" data-name=\"#{name}\">#{name}</span></td>\n  <td class=\"body\">\n    <div>has left the room</div>\n    \n\n\n  </td>\n</tr>\n"),
  upload_message: new Template("<tr class=\"message upload_message\" id=\"message_#{id}\"><td class=\"person\"><span class=\"author\" data-avatar=\"#{avatar}\" data-email=\"#{email_address}\" data-name=\"#{name}\">#{name}</span></td>\n  <td class=\"body\">\n    <div class=\"body\"><img alt=\"Icon_png_small\" class=\"file_icon\" height=\"18\" src=\"/images/icons/icon_PNG_small.gif?1331159708\" width=\"24\">\n<a href=\"#{full_url}\" target=\"_blank\" title=\"#{body}\">#{body}</a>\n</div>\n    \n\n\n  </td>\n</tr>\n"),
  upload_message_image: new Template("<tr class=\"message upload_message\" id=\"message_#{id}\"><td class=\"person\"><span class=\"author\" data-avatar=\"#{avatar}\" data-email=\"#{email_address}\" data-name=\"#{name}\">#{name}</span></td>\n  <td class=\"body\">\n    <div class=\"body\"><img alt=\"Icon_png_small\" class=\"file_icon\" height=\"18\" src=\"/images/icons/icon_PNG_small.gif?1331159708\" width=\"24\">\n<a href=\"#{full_url}\" target=\"_blank\" title=\"#{body}\">#{body}</a>\n<br>\n<a href=\"#{full_url}\" class=\"image\" target=\"_blank\"><img alt=\"#{body}\" onerror=\"$dispatch('inlineImageLoadFailed', this)\" onload=\"$dispatch('inlineImageLoaded', this)\" src=\"#{thumb_url}\"></a></div>\n    \n\n\n  </td>\n</tr>\n"),
  timestamp_message: new Template("<tr class=\"message timestamp_message\" id=\"message_#{id}\"><td class=\"date\"><span class=\"author\" style='display:none'></span></td>\n  <td class=\"time\">\n    <div class='body'>#{time}</div>\n    \n\n\n  </td>\n</tr>\n"),
}

var i = new Image(); i.src = "https://github.com/images/spinners/octocat-spinner-16px.gif"

function preloadUsers(cb) {
  if (window.chat.usersById) {
    cb()
    return
  }

  new JsonpRequest(
    'https://search.githubapp.com/campfire/user/_search',
    function(data) {
      if (data.authorize_url) {
        // alert(JSON.stringify(window.location.toString()))
        // alert(JSON.stringify(encodeURIComponent(window.location.toString())))
        // alert(data.authorize_url)
        window.location = data.authorize_url
      } else {
        var users = data.hits.hits.map(function(h){ return h._source })
        window.chat.usersById = $H()
        users.each(function(u){
          window.chat.usersById[ u.id ] = u
        })
        cb()
      }
    },
    {
      param: {
        size: 1000
      }
    }
  )
}


function prependHistory(cb) {
  var room_id = $('return_to_room_id').value
  var earliest_message = $('todays_transcript_link').href.match(/(\d+)$/)[1]
  var history_request = 'history_request_' + (new Date().getTime())

  new JsonpRequest(
    'https://search.githubapp.com/campfire/_search',
    function(data){
      if (data.authorize_url) {
        window.location = data.authorize_url
      } else {
        var ids = []
        var html = ''

        var hits = data.hits.hits.reverse()
        hits.each(function(msg){
          var type = msg._type
          var src = msg._source
          var tmpl = Campfire.Transcript.messageTemplates[ type ]
          var user = chat.usersById[ src.user_id ]

          if (tmpl) {
            var opts;
            if (user)
              opts = $H(user)
            else
              opts = $H({})

            if (src.body)
              opts = opts.merge({body: chat.transcript.bodyForPendingMessage(src.body)})
            if (src.full_url) {
              opts = opts.merge({full_url: src.full_url, thumb_url: src.full_url.replace('uploads', 'thumb')})
            }
            if (src.content_type && src.content_type.match(/image/)) {
              tmpl = Campfire.Transcript.messageTemplates[ 'upload_message_image' ]
            }
            if (opts.get('body') && type == 'paste_message') {
              // Limit the body to 16 lines.
              var lines = opts.get('body').split("\n");
              if (lines.length > 16)
                opts.set('body', lines.slice(0, 16).join("\n") + "\n...");
            }


            var date = new Date(src.created_at)
            var hours = date.getHours()
            var mins = date.getMinutes() + ''
            if (mins.length == 1)
              mins = '0' + mins
            var time = (hours > 12 ? hours-12 : hours == 0 ? 12 : hours) + ':' + mins + ' ' + (hours >= 12 ? 'PM' : 'AM')

            html += tmpl.evaluate(opts.merge({id: src.id, time: time, room_id: src.room_id, tweet: src.tweet}))
            ids.push(src.id)
          }
        })

        if (ids.length) {
          new Insertion.Top(chat.transcript.element, "<tr id='"+history_request+"'><td colspan=2><img src='https://github.com/images/spinners/octocat-spinner-16px.gif'></td></tr>")
          $(history_request).scrollTo()
          var scrollBottom = document.body.scrollHeight - document.body.scrollTop;
          var maintainScrollPosition = function() {
            document.body.scrollTop = document.body.scrollHeight - scrollBottom;
          }

          // Images without explicit sizes, and iframes whose src URLs contain
          // fragments, can cause the transcript to shift or scroll. We work
          // hard to keep the scroll position the same distance from the bottom
          // while backfilling.
          var interval = setInterval(maintainScrollPosition, 0);

          setTimeout(function(){
            chat.messageHistory += ids.length
            chat.transcript.prependMessages.apply(chat.transcript, [maintainScrollPosition, html].concat(ids))

            setTimeout(function(){
              $(history_request).remove()
              maintainScrollPosition()
              // Give iframes and images some more time to load before we let
              // the scroll position go.
              setTimeout(function(){
                clearInterval(interval);
              }, 1000)
            }, 250)
          }, 400)

          var link = $('todays_transcript_link');
          link.href = link.href.replace(/\/\d+$/, '/' + hits[0]._id);
        }
      }

      if (cb)
        cb()
    },
    {
      param: $H({
        q: 'room_id:' + room_id + ' AND id:[* TO ' + (parseInt(earliest_message)-1) + ']',
        size: 100,
        sort: 'id:desc'
      })
    }
  )
}

$('todays_transcript_link').onclick = function(ev){
  ev.preventDefault()
  preloadUsers(function(){
    prependHistory()
  })
}
if (location.search.match(/backfill/)) {
  preloadUsers(function(){
    prependHistory()
  })
}

new Insertion.Bottom($('todays_transcript'), "<div style='float:right' id='infinite_scroll'></div>")

var triggerHistory = false, triggeringHistory = false
Event.observe(window, 'scroll', function(ev) {
  var top = document.viewport.getScrollOffsets()[1]
  if (top < -40) {
    triggerHistory = true
  }

  if (triggeringHistory)
    $('infinite_scroll').update('backfilling..')
  else if (triggerHistory)
    $('infinite_scroll').update('let go to backfill')
  else if (top < 0)
    $('infinite_scroll').update('keep pulling down to backfill')
  else if (top >= 0)
    $('infinite_scroll').update('')

  if (triggerHistory && top >= -5) {
    triggerHistory = false
    triggeringHistory = true
    preloadUsers(function(){
      prependHistory(function(){
        triggeringHistory = false
        $('infinite_scroll').update('')
      })
    })
  }

});

/* end infinite scroll */