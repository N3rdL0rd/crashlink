import haxe.Int32;

class Anonymous {
    static function main() {
        var a = { first: 3, second: 4 };
        log(a.first, a.second, 5);
    }

    static function log(argument_name_cannot_be_confused_at_all: Dynamic, other_arg_name: Int32, third_arg: Dynamic) {
        trace(argument_name_cannot_be_confused_at_all);
    }
}