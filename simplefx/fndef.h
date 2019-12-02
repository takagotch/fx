
#ifndef SRC_DIMPLEFX_FNDEF_H_
#define SRC_SIMPLEFX_FNDeF_H_

#include <functional>

#include "../main/istockapi.h"

using Command = std::function<double(double)>;

using OnPriceChange = std::function<bool(const IStockApi::Ticker &price)>;

using RegisterPriceChangeEvent = std::function<void(OnPriceChange &&cb)>;

#endif


