enum Color {
	Red;
	Green;
	Blue;
}

class EnumMapStaticInit {
	public static var names:Map<Color, String> = buildNames();

	static function buildNames():Map<Color, String> {
		var m = new Map<Color, String>();
		m.set(Red, "red");
		m.set(Green, "green");
		m.set(Blue, "blue");
		return m;
	}

	static function main() {
		trace(names.get(Red));
		trace(names.get(Green));
		trace(names.get(Blue));
		names.set(Red, "RED2");
		trace(names.get(Red));
	}
}
