vcl 4.0;

import std;
import digest;
import crypto;
import blob;


sub vcl_init {
  new v = crypto.verifier(sha256, std.getenv("PUBLIC_KEY"));
}

backend default {
  .host = "%%BACKEND_HOST%%";
  .port = "80";
}

# Hosts allowed to send BAN requests
acl invalidators {
  "localhost";
  # local Docker/Kubernetes network
  "10.0.0.0"/8;
  "172.16.0.0"/12;
  "192.168.0.0"/16;
}

sub vcl_recv {
  # Remove the "Forwarded" HTTP header if exists (security)
  unset req.http.forwarded;
  # To allow API Platform to ban by cache tags
  if (req.method == "BAN") {
    if (client.ip !~ invalidators) {
      return (synth(405, "Not allowed"));
    }
    if (req.http.ApiPlatform-Ban-Regex) {
      ban("obj.http.Cache-Tags ~ " + req.http.ApiPlatform-Ban-Regex);
      return (synth(200, "Ban added"));
    }
    return (synth(400, "ApiPlatform-Ban-Regex HTTP header must be set."));
  }
  #bypass cache when no-cache or private header is present
  if (req.http.cache-control ~ "(no-cache|private)" ||
      req.http.pragma ~ "no-cache") {
         return (pass);
  }

  if (req.method != "GET" && req.method != "HEAD") {
    return (pass);
  }

  # For health checks
  if (req.method == "GET" && req.url == "/healthz") {
    return (synth(200, "OK"));
  }

  if (req.url != "/refresh_token" && req.url != "/authentication_token" && req.url != "/docs" && req.url != "/docs.json" && req.url !~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
      set req.http.x-token = regsuball(req.http.Authorization, "Bearer ", "");

      set req.http.tmpHeader = regsub(req.http.x-token,"([^\.]+)\.[^\.]+\.[^\.]+","\1");
      set req.http.tmpTyp = regsub(digest.base64_decode(req.http.tmpHeader),{"^.*?"typ"\s*:\s*"(\w+)".*?$"},"\1");
      set req.http.tmpAlg = regsub(digest.base64_decode(req.http.tmpHeader),{"^.*?"alg"\s*:\s*"(\w+)".*?$"},"\1");


      if(req.http.tmpTyp != "JWT") {
          return(synth(401, "Invalid JWT Token: Token is not a JWT: " + req.http.tmpHeader));
      }
      if(req.http.tmpAlg != "RS256") {
          return(synth(401, "Invalid JWT Token: Token does not use RS256 hashing"));
      }

      set req.http.tmpPayload = regsub(req.http.x-token,"[^\.]+\.([^\.]+)\.[^\.]+$","\1");
      set req.http.tmpRequestSig = regsub(req.http.x-token,"^[^\.]+\.[^\.]+\.([^\.]+)$","\1");

      v.update(req.http.tmpHeader + "." + req.http.tmpPayload );


      if (! v.valid( blob.decode(BASE64URLNOPAD, encoded=req.http.tmpRequestSig))) {
          return (synth(401, "Invalid JWT Token: Signature"));
      }

      set req.http.X-Expiration = regsub(digest.base64_decode(req.http.tmpPayload), {"^.*?"exp":([0-9]+).*?$"},"\1");

      if (std.integer(req.http.X-Expiration, 0) <  std.time2integer(now, 0)) {
          return (synth(401, "Invalid JWT Token: Token expired"));
      }

      unset req.http.tmpHeader;
      unset req.http.tmpTyp;
      unset req.http.tmpAlg;
      unset req.http.tmpPayload;
      unset req.http.tmpRequestSig;

      return (hash);
  }
}

sub vcl_hit {
    if (obj.ttl >= 0s) {
        // A pure unadultered hit, deliver it
        return (deliver);
    }
    if (obj.ttl + obj.grace > 0s) {
        // Object is in grace, deliver it
        // Automatically triggers a background fetch
        return (deliver);
    }

    return (pass);
}


sub vcl_deliver {
  # Don't send cache tags related headers to the client
  unset resp.http.url;
  # Remove Via header with varnish details
  unset resp.http.Via;
  # Comment the following line to send the "Cache-Tags" header to the client (e.g. to use CloudFlare cache tags)
  unset resp.http.Cache-Tags;

  if (obj.hits > 0) {
          set resp.http.X-Cache = "HIT";
  } else {
          set resp.http.X-Cache = "MISS";
  }

  # For private api, change this sentence with:
  # if (req.http.Origin == "https://www.example.com" ...
  if (req.http.Origin) {
    set resp.http.Access-Control-Allow-Origin = req.http.Origin;
    set resp.http.Access-Control-Allow-Credentials = "true";
  }

  if (resp.http.Vary) {
    set resp.http.Vary = resp.http.Vary + ",Origin";
  } else {
    set resp.http.Vary = "Origin";
  }
}

sub vcl_backend_response {
  # Ban lurker friendly header
  set beresp.http.url = bereq.url;

  # Add a grace in case the backend is down
  set beresp.grace = 1h;
}


sub vcl_synth {
    set resp.http.Content-Type = "application/json";
    set resp.http.Access-Control-Allow-Origin = "*";
    set resp.http.Access-Control-Allow-Credentials = "true";

    synthetic( {"{ "code":"} + resp.status + {", "message": ""} + resp.reason + {"" }"} );

    return (deliver);
}
