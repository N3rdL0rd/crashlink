class OrderOfEval {
	static var log:Array<String> = [];

	static function side(name:String, v:Int):Int {
		log.push(name);
		return v;
	}

	static function take(a:Int, b:Int, c:Int):Int {
		return a * 100 + b * 10 + c;
	}

	static function main() {
		log = [];
		var r = take(side("a", 1), side("b", 2), side("c", 3));
		trace(r);
		trace(log.join(","));

		// side effects in array index expressions
		log = [];
		var arr = [10, 20, 30];
		arr[side("idx", 1)] = side("val", 99);
		trace(arr.join(","));
		trace(log.join(","));

		// side effect order in binary op
		log = [];
		var x = side("left", 5) + side("right", 7) * side("mul", 2);
		trace(x);
		trace(log.join(","));
	}
}
