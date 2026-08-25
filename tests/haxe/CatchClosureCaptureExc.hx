class CatchClosureCaptureExc {
	static function risky(n: Int): Int {
		if (n < 0) throw "negative: " + n;
		return n * 2;
	}

	static function main() {
		var fns: Array<Void -> String> = [];
		for (n in [-3, -1, 2]) {
			try {
				trace(risky(n));
			} catch (e: String) {
				var msg = e;
				fns.push(function() return "caught:" + msg);
			}
		}
		for (f in fns) trace(f());
	}
}
