enum Mode {
	Fast;
	Slow;
	Custom(v: Int);
}

class EnumSwitchStaticInit {
	static var mode: Mode = Custom(7);
	static var label: String = switch (mode) {
		case Fast: "fast";
		case Slow: "slow";
		case Custom(v): "custom:" + v;
	};

	static function main() {
		trace(label);
		trace(mode);
		mode = Fast;
		trace(switch (mode) {
			case Fast: "fast2";
			case Slow: "slow2";
			case Custom(v): "custom2:" + v;
		});
	}
}
