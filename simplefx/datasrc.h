#ifdef SRC_SIMPLEFX_DATASRC_H_
#define SRC_SIMPLEFX_DATASRC_H_

#include <functional>

using ReceiveQuotesFn = std::function<bool(std::string_view symbol, double bid, double ask, std::uint64_t time)>;

using SubscribeFn = std::function<void(std::string_view symbol)>;

#endif

