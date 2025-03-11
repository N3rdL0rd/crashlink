class Arithmetic {
    static function main() {
        var first_var = 3;
        var second_var = 4;
        var third_var = first_var;
        var test = "test!!!";
        var res = first_var + second_var;
        var res2 = first_var - second_var;
        var res3 = first_var * second_var;
        var res4 = first_var / second_var;
        var res5 = first_var % second_var;
        var res6 = first_var << second_var;
        var bool_res = first_var < second_var; // true
        if (bool_res) {
            var final_res = first_var + second_var;
        } else {
            var final_res = first_var - second_var;
        }
        if (first_var < second_var) {
            var final_res = first_var + second_var;
        } else {
            var final_res = first_var - second_var;
        }
    }
}