class QualityEffects {
    public var total:Int;

    public function new() {
        total = 2;
    }

    @:keep @:noInline public function update(input:Int):Int {
        total = total + input;
        if (input < 0) throw "negative";
        return total * 3;
    }

    public static function main():Void {
        var state = new QualityEffects();
        Sys.println(state.update(4));
        Sys.println(state.total);
        try {
            state.update(-5);
        } catch (error:Dynamic) {
            Sys.println(Std.string(error));
        }
        Sys.println(state.total);
        var index = 0;
        while (index < 3) {
            Sys.println(index);
            index++;
        }
    }
}
