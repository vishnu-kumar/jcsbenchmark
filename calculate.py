def PercentileCalculator(numbers):
  numbers_sorted = sorted(numbers)
  count = len(numbers_sorted)
  total = sum(numbers_sorted)
  result = {}
  result['p1'] = numbers_sorted[int(count * 0.01)]
  result['p5'] = numbers_sorted[int(count * 0.05)]
  result['p50'] = numbers_sorted[int(count * 0.5)]
  result['p90'] = numbers_sorted[int(count * 0.9)]
  result['p99'] = numbers_sorted[int(count * 0.99)]
  result['p99.9'] = numbers_sorted[int(count * 0.999)]
  if count > 0:
    average = total / float(count)
    result['average'] = average
    if count > 1:
      total_of_squares = sum([(i - average) ** 2 for i in numbers])
      result['stddev'] = (total_of_squares / (count - 1)) ** 0.5
    else:
      result['stddev'] = 0

  return result
import sys
if __name__ == "__main__":
	if( len(sys.argv) != 2):
		print "not desired args"
		exit()
	fileName = sys.argv[1]
	fileH  = open(fileName, "r")
	numbers = []
	for line in fileH.readlines():
		t = line.split("Boot Time")[1].split("seconds")[0]
		print t
		numbers.append(float(t.strip()))

	print PercentileCalculator(numbers)
