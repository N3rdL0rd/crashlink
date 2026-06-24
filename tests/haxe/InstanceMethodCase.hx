class InstanceMethodCase {
    var value: Int;

    public function new() {
        this.value = 10;
    }

    public function getValue(): Int {
        return this.value;
    }

    public static function main(): Void {
        var instance = new InstanceMethodCase();
        var v = instance.getValue();
    }
}
