$(function method_detail() {
    $('#select').on("change", function (e, data) {
        var method_id = $(this).children(":selected").attr("id");
        console.log(e);
        $.ajax({
            url: "method/".concat(method_id).concat('/'),
            data: method_id,
            success: function (data) {
                $('#method_info').html(data);
            }
        });
    });
});