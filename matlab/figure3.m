markers = ["-o","-x","-s","-d","-+","-p"];

% Load data
simulation_data_figure3

% Create figures folder
if ~exist('../figures', 'dir')
   mkdir('../figures')
end


% First figure - Malicious devices quarantined
figure
hold on
grid on
clear legend
legend = legend('show','Location','southwest');

for i = 1:length(malicious_devices_prop)
    errorbar(threshold_ratio, malicious_quarantined(i,:), malicious_quarantined_errorbars(i,:), markers(i),'MarkerSize',7,'LineWidth',1,'DisplayName',sprintf('%.3f malicious', malicious_devices_prop(i)))
end

axis([1.0000    1.1500    0.5500    1.0000])
xticks([1:0.015:1.15]);
xlabel('Threshold')
ylabel('Malicious devices quarantined')
saveas(gcf,'../figures/figure_3_1','png')
print -depsc -r600 ../figures/figure_3_1.eps


% Second figure - Legitimate devices quarantined
figure
hold on
grid on
clear legend
legend = legend('show','Location','southwest');

for i = 1:length(malicious_devices_prop)
    errorbar(threshold_ratio(2:end), legitimate_quarantined(i,2:end), legitimate_quarantined_errorbars(i,2:end), markers(i),'MarkerSize',7,'LineWidth',1,'DisplayName',sprintf('%.3f malicious', malicious_devices_prop(i)))
end

axis([1.0000    1.1500    0.0000    1.0000])
xticks([1:0.015:1.15]);
xlabel('Threshold')
ylabel('Legitimate devices quarantined')
saveas(gcf,'../figures/figure_3_2','png')
print -depsc -r600 ../figures/figure_3_2.eps