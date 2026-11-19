### Added

- Capacity forecasting: each subnet's utilization history now projects when it will be full. A "full in N d" caption sits beside the utilization bar in the subnet tables, the Trend tab states the projected date, `GET /api/v1/ipam/subnets/capacity-forecast` returns the forecasts, a new `subnet_capacity_forecast` alert rule fires when a subnet will fill within a set number of days, and the Copilot gets a `find_subnet_forecasts` tool. No forecast is shown for a flat or falling trend, under 14 days of history, or a prefix excluded from utilization. (#43)
