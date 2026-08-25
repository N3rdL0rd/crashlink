interface IA {
	function greet():String;
}

interface IB {
	function greet():String;
}

class Both implements IA implements IB {
	public function new() {}
	public function greet():String {
		return "hello from both";
	}
}

class InterfaceDiamond {
	static function main() {
		var b = new Both();
		var a:IA = b;
		var c:IB = b;
		trace(a.greet());
		trace(c.greet());
		trace(b.greet());
	}
}
