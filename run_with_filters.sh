#!/bin/bash
# Script to run the security scanner with different filtering options

echo "Security Scanner Output Filtering Options"
echo "----------------------------------------"
echo

echo "1. Run with default filtering (INFO level and command filtering enabled):"
echo "   python3 run.py"
echo

echo "2. Run with no filtering (all output shown):"
echo "   python3 run.py --no-filter"
echo

echo "3. Run with WARNING level filtering (only WARNING and above):"
echo "   python3 run.py --log-level WARNING"
echo

echo "4. Run with INFO level but disable command filtering:"
echo "   python3 run.py --log-level INFO --filter-commands false"
echo

echo "5. Run with custom filter patterns (filter out any logs with 'neural' or 'ML'):"
echo "   python3 run.py --filter-pattern 'neural' --filter-pattern 'ML'"
echo

echo "6. Run with ERROR level only (only show errors and critical messages):"
echo "   python3 run.py --log-level ERROR"
echo

echo "7. Run with neural pattern messages specifically filtered:"
echo "   python3 run.py --filter-pattern 'Neural pattern input insufficient' --filter-pattern 'padding with zeros'"
echo

# Usage examples
if [ "$1" == "1" ]; then
  python3 run.py
elif [ "$1" == "2" ]; then
  python3 run.py --no-filter
elif [ "$1" == "3" ]; then
  python3 run.py --log-level WARNING
elif [ "$1" == "4" ]; then
  python3 run.py --log-level INFO --filter-commands false
elif [ "$1" == "5" ]; then
  python3 run.py --filter-pattern "neural" --filter-pattern "ML"
elif [ "$1" == "6" ]; then
  python3 run.py --log-level ERROR
elif [ "$1" == "7" ]; then
  python3 run.py --filter-pattern "Neural pattern input insufficient" --filter-pattern "padding with zeros"
else
  echo "To run an example, use: ./run_with_filters.sh [1-7]"
  echo "For example: ./run_with_filters.sh 2"
fi 