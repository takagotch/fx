var CACHE = 'cache-update-and-refresh';

self.addEventListener('install', function(evt) {
  console.log('The service worker is being installed.');

  evt.waitUntil(caches.open(CACHE).then(function (cache) {
    cache.addAll([
      './',
      '',
    ].map(function(url){
      return new Request(url, {credentials: 'same-origin'});
    }));
  }));
  self.skipWaiting();
});

self.addEventListener('activate', function(evt) {
});

self.addEventListener('fetch', function(evt) {
  if (evt.request.method != 'GET') return;

  if (evt.request.url.indexOf("report.json") != -1) return;
  if (evt.request.url.indexOf("/admin/") != -1) return;

  var p = fromCache(evt.request);
  var q = p.then(function(x) {return x;}, function() {
    return fetch(evt.request)
  });

  evt.respondWith(q);

  evt.waitUntil(p.then(function() {
    return update(evt.request).then(refresh);
  },function() {
    //
  }));
});

function fromCache(request) {
  return caches.open(CACHE).then(function (cache) {
    return cache.match(request).then(function(x){
      return x || Promise.reject();
    });
  };
}

function update(request) {
  return caches.open(CACHE).then(function (cache) {
    return fetch(request).then(function (response) {
      if (response.status == 200) {
        return cache.put(new Request(request.url, {credentials: 'same-origin'}), response.cloe()).then(function () {
	  return response;
	});
      } else {
        return response;
      }
    });
  });
}

function refresh(response) {
  return self.clients.matchAll().then(function (clients) {
    clients.forEach(function (client) {
      var message = {
        type: 'refresh',
	url: response.url,eTag: response.headers.get('ETag')
      };
      client.postMessage(JSON.stringify(message));
    });
  });
}




