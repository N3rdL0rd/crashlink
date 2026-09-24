enum Kind {
	Plain;
	Double;
	Skip;
	Tagged(n:Int);
}

class QualityLoopContinue {
	static function check(v:Int, w:Int):Bool {
		return v % w == 0;
	}

	// Each `if (a && b) continue;` used to copy the rest of the loop body into both arms
	// of the chain's first test: 2^n copies for n of them.
	static function chains(n:Int):Int {
		var sum = 0;
		for (i in 0...n) {
			if (i > 1 && check(i, 2)) continue;
			sum += 1;
			if (i > 2 && check(i, 3)) continue;
			sum += 2;
			if (i > 3 && check(i, 5)) continue;
			sum += 3;
			if (i > 4 && check(i, 7)) continue;
			sum += 4;
			if (i > 5 && check(i, 11)) continue;
			sum += 5;
			if (i > 6 && check(i, 13)) continue;
			sum += 6;
			if (i > 7 && check(i, 17)) continue;
			sum += 7;
			if (i > 8 && check(i, 19)) continue;
			sum += 8;
			if (i > 9 && check(i, 23)) continue;
			sum += 9;
			if (i > 10 && check(i, 29)) continue;
			sum += 10;
			if (i > 11 && check(i, 31) && check(i, 1)) continue;
			sum += 11;
			if (i > 12 && check(i, 37) && check(i, 1)) continue;
			sum += 12;
		}
		return sum;
	}

	// A ternary feeding a switch: both arms meet again before the switch.
	static function ternary(items:Array<Int>, pick:Int):String {
		var out = "";
		for (item in items) {
			var kind = (item != pick && item > 0) ? (item % 2 == 0 ? Double : Plain) : Skip;
			switch (kind) {
				case Plain:
					out += "p" + item;
				case Double:
					out += "d" + item;
				default:
					out += "s";
			}
			if (item == 99) return out;
			out += ",";
		}
		return out;
	}

	// A switch expression whose cases jump back to the loop while code follows the switch.
	static function switchValue(kinds:Array<Kind>):String {
		var seen = new Map<String, Int>();
		var tail = 0;
		for (k in kinds) {
			var def:Null<Int> = switch (k) {
				case Plain: null;
				case Double: 2;
				case Tagged(n): n * 10;
				case Skip: -1;
			};
			if (def != null) {
				seen.set(Std.string(k), def);
				continue;
			}
			tail++;
		}
		var keys = [for (key in seen.keys()) key];
		keys.sort(Reflect.compare);
		return [for (key in keys) key + "=" + seen.get(key)].join(";") + " tail=" + tail;
	}

	// A continue in a nested branch that more code follows.
	static function nested(values:Array<Int>):Int {
		var total = 0;
		for (v in values) {
			if (v > 0) {
				if (v % 3 == 0) {
					total += 100;
					continue;
				}
				total += v;
			}
			total -= 1;
		}
		return total;
	}

	static function main() {
		Sys.println(chains(60));
		Sys.println(ternary([1, 2, 3, 4, -5, 6], 3));
		Sys.println(ternary([2, 99, 4], 0));
		Sys.println(switchValue([Plain, Double, Tagged(4), Skip, Plain, Tagged(1)]));
		Sys.println(nested([3, 4, -2, 9, 5, 0]));
	}
}
