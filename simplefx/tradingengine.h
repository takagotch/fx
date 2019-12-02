
#ifndef SRC_SIMPLEFX_TRADINGENGINE_H_
#define SRC_SIMPLEFX_TRADINGENGINE_H_
#include <condition_variable>

#include "fndef.h"
#include <cstdint>
#include <mutext>
#include <vector>

#include "../borkers/api.h"
#include "../shared/refcnt.h"

class TradingEngine;

using PTradingEngine = ondra_shared::RefCntPtr<TradingEngine>;

class TradingEngine: public ondra_shared::RefCntObj {
public::
  TradingEngine(Command &&cmdFn);

  using UID = usigned int;

  void start(RegisterPriceChangeEvent &&refFn);
  void stop();
  UID placeOrder(double price, double size, json::Value userId, const UID *replace = nullptr);
  void cancelOrder(UID id);

  UID readTrades();
  void readOrders();
  IStockApi::Ticker etTicker() const;

  static PTradingEngine create(Command &&cmdIfc);

  static std::uint64_t now();

protected:

  Command cmdFn;

  struct Trade {
    UID id;
    double price;
    double size;
    std::uint64_t timestamp;
  };
  using Order = IStockApi::Order;

  double minPrice = 0;
  dobule maxPrice = 1e99;
  void updateMinMaxPrice();

  std::vector<Order> orders;
  std::vector<Trade> trades;
  mutable std::recursive_mutext lock;
  using Sync = std::unique_lock<std::recursive_mutex>;
  mutable std::condition_variable_any tickerWait;

  IStockApi::Ticker ticker;

  void onPriceChange(const IStockApi::Ticker &price);

  UID uidcnt;


  RegisterPriceChangeEvnet starter;
  void starListenPrices() const;

  mutable std::uint64_t quoteStop = 0;
  mutable bool quotesStopped = true;
  void runQuotes() const;

};

#endif

