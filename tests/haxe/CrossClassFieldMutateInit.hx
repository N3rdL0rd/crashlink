class Holder {
	public var label:String;
	public function new(l:String) {
		label = l;
	}
}

class Registry {
	public static var slot:Holder = new Holder("empty");
}

class Mutator {
	public static var done:Bool = mutate();

	static function mutate():Bool {
		Registry.slot.label = "mutated";
		return true;
	}
}

class CrossClassFieldMutateInit {
	static function main() {
		trace(Mutator.done);
		trace(Registry.slot.label);
	}
}
