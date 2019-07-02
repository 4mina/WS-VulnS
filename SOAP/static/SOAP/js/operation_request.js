$(function () {
    $('#operations-group').change(function () {
        var selected_operation = $(this).find("option:selected");
        var selected_operation_id = selected_operation.val();

        $.ajax({
            url: "operation_request/".concat(selected_operation_id).concat("/"),
            data: selected_operation_id,
            success: function(data) {
                $("#operation-request").html(data);
            }
        });
    });

    /*var editor = CodeMirror.fromTextArea(document.getElementById('text-area'), {
        lineNumbers: true
    });*/
});