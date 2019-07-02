$(function () {
    $('#endpoints-group').change(function () {
        var selected_endpoint = $(this).find("option:selected");
        var selected_endpoint_id = selected_endpoint.val();

        $.ajax({
            url: 'load_operations/',
            data: {'endpoint_id': selected_endpoint_id},
            success: function(data){
                console.log(data);
                var options = ''
                for (var i = 0 ; i < data.length ; i++)
                {
                   options += '<option value="' + data[i].id + '">' + data[i].name + '</option>';
                }
                $("#operations-group").html(options);
            }
        });
    });
});