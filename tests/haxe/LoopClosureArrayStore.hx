class LoopClosureArrayStore {
	static function main() {
		var callbacks = [];
		for (i in 0...3) {
			var captured = i;
			callbacks.push(function() return captured);
		}
		for (cb in callbacks) trace(cb());
		trace(callbacks[0] == callbacks[1]);
		trace(callbacks[0]());
	}
}
