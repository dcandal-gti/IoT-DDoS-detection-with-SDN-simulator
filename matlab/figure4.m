markers = ["-o","-x","-s","-d","-+","-p"];

% Load data
simulation_data_figure4

% Create figures folder
if ~exist('../figures', 'dir')
   mkdir('../figures')
end


% First figure - Malicious devices quarantined
figure
hold on
grid on
clear legend
legend = legend('show','Location','southeast');

for i = 1:length(malicious_devices_prop)
    errorbar(malicious_frequency_multiplier, malicious_quarantined(i,:), malicious_quarantined_errorbars(i,:), markers(i),'MarkerSize',7,'LineWidth',1,'DisplayName',sprintf('%.3f malicious', malicious_devices_prop(i)))
end

axis([0    200    0    1.0000]);
xticks([0:20:200]);
xlabel('Transmission frequency, malicious/genuine')
ylabel('Malicious devices quarantined')
saveas(gcf,'../figures/figure_4_1','png')
print -depsc -r600 ../figures/figure_4_1.eps


% Second figure - Legitimate devices quarantined
figure
hold on
grid on
clear legend
legend = legend('show','Location','southeast');

for i = 1:length(malicious_devices_prop)
    errorbar(malicious_frequency_multiplier, legitimate_quarantined(i,:), legitimate_quarantined_errorbars(i,:), markers(i),'MarkerSize',7,'LineWidth',1,'DisplayName',sprintf('%.3f malicious', malicious_devices_prop(i)))
end

axis([0    200    0    1.0000]);
xticks([0:20:200]);
xlabel('Transmission frequency, malicious/genuine')
ylabel('Legitimate devices quarantined')
saveas(gcf,'../figures/figure_4_2','png')
print -depsc -r600 ../figures/figure_4_2.eps