enum abstract Color(Int) {
	var Red = 1;
	var Green = 2;
	var Blue = 4;

	public function toName():String {
		return switch (cast this : Color) {
			case Red: "red";
			case Green: "green";
			case Blue: "blue";
			default: "unknown";
		}
	}
}

class EnumAbstractFlags {
	static function main() {
		var c:Color = Green;
		trace(c.toName());
		trace(c);
		var flags:Int = cast(Red, Int) | cast(Blue, Int);
		trace(flags);
	}
}
